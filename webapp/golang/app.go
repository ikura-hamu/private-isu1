package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db                *sqlx.DB
	store             *gsm.MemcacheStore
	commentCache      CommentCache
	commentCountCache CommentCountCache
	accountNameCache  AccountNameCache
)

type CommentCache struct {
	items map[int]*[]Comment
	mu    sync.Mutex
}

func (c *CommentCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[int]*[]Comment)
}

func (c *CommentCache) getCommentCache(key int) (*[]Comment, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	comments, ok := c.items[key]
	return comments, ok
}

func (c *CommentCache) setCommentCache(key int, comments []Comment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = &comments
}

func (c *CommentCache) updateCommentCache(key int, comment Comment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := len(*c.items[key])
	if l >= 3 {
		c.items[key] = &[]Comment{(*c.items[key])[1], (*c.items[key])[2], comment}
	} else if l > 0 {
		cc := append(*c.items[key], comment)
		c.items[key] = &cc
	} else {
		c.items[key] = &[]Comment{comment}
	}
}

type CommentCountCache struct {
	items map[int]*int
	mu    sync.Mutex
}

func (c *CommentCountCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[int]*int)
}

func (c *CommentCountCache) getCommentCountCache(key int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var count *int
	count, ok := c.items[key]
	if ok {
		return *count
	}

	var co int
	err := db.Get(&co, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", key)
	if err != nil {
		log.Printf("failed to get comment count: %v", err)
		return 0 //ほんとは0は良くない
	}
	c.items[key] = &co

	return co
}

func (c *CommentCountCache) addCommentCountCache(key int, diff int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if *c.items[key] == 0 {
		c.items[key] = &diff
		return
	}

	n := *c.items[key] + diff
	c.items[key] = &n
}

type AccountNameCache struct {
	items map[int]*string
	mu    sync.Mutex
}

func (c *AccountNameCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[int]*string)
}

func (c *AccountNameCache) getUserNameCache(key int) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return *c.items[key]
}

func (c *AccountNameCache) setUserNameCache(key int, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &name
}

func (c *AccountNameCache) initUserNameCache(users []User) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range users {
		c.items[users[i].ID] = &users[i].AccountName
	}
}

const (
	postsPerPage     = 20
	ISO8601Format    = "2006-01-02T15:04:05-07:00"
	UploadLimit      = 10 * 1024 * 1024 // 10mb
	imagesFolderPath = "../public/image/"
)

var (
	getIndexTemp = template.Must(
		template.New("layout.html").
			Funcs(template.FuncMap{
				"imageURL": imageURL,
			}).
			ParseFiles(
				getTemplPath("layout.html"),
				getTemplPath("index.html"),
				getTemplPath("posts.html"),
				getTemplPath("post.html"),
			))
	getAccountNameTemp = template.Must(
		template.New("layout.html").
			Funcs(template.FuncMap{
				"imageURL": imageURL,
			}).
			ParseFiles(
				getTemplPath("layout.html"),
				getTemplPath("user.html"),
				getTemplPath("posts.html"),
				getTemplPath("post.html"),
			))
	getPostsTemp = template.Must(
		template.New("posts.html").
			Funcs(template.FuncMap{
				"imageURL": imageURL,
			}).
			ParseFiles(
				getTemplPath("posts.html"),
				getTemplPath("post.html"),
			))
	getPostsIdTemp = template.Must(
		template.New("layout.html").Funcs(template.FuncMap{
			"imageURL": imageURL,
		}).
			ParseFiles(
				getTemplPath("layout.html"),
				getTemplPath("post_id.html"),
				getTemplPath("post.html"),
			))
	getAdminBannedTemp = template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	)
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User `db:"user"`
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"user"`
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	var users []User
	err := db.Select(&users, "SELECT `id`, `account_name` FROM `users`")
	if err != nil {
		log.Printf("failed to get users: %v", err)
		return
	}
	accountNameCache.initUserNameCache(users)
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	h := sha512.New()
	_, err := h.Write([]byte(src))
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(hex.EncodeToString(h.Sum(nil)), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	for _, p := range results {
		// err := db.Get(&p.User, "SELECT * FROM `users` WHERE `id` = ?", p.UserID)
		// if err != nil {
		// 	return nil, err
		// }

		p.CSRFToken = csrfToken

		// if p.User.DelFlg != 0 {
		// 	continue
		// }

		p.CommentCount = commentCountCache.getCommentCountCache(p.ID)

		query := "SELECT `comments`.*, users.id AS `user.id`, users.account_name AS `user.account_name` FROM `comments` JOIN `users` ON comments.user_id = users.id WHERE comments.post_id = ? ORDER BY comments.created_at DESC"

		if !allComments {
			query += " LIMIT 3"
			c, ok := commentCache.getCommentCache(p.ID)
			if ok {
				p.Comments = *c
				posts = append(posts, p)

				if len(posts) >= postsPerPage {
					break
				}
				continue
			} else {
				var comments []Comment
				err := db.Select(&comments, query, p.ID)
				if err != nil {
					return nil, err
				}
				for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
					comments[i], comments[j] = comments[j], comments[i]
				}
				commentCache.setCommentCache(p.ID, comments)
				p.Comments = comments
				posts = append(posts, p)

				if len(posts) >= postsPerPage {
					break
				}
				continue
			}
		}

		var comments []Comment
		err := db.Select(&comments, query, p.ID)
		if err != nil {
			return nil, err
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments

		posts = append(posts, p)

		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	commentCache.Reset()
	commentCountCache.Reset()
	accountNameCache.Reset()

	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	accountNameCache.setUserNameCache(int(uid), accountName)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []Post{}

	// q := "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.id AS `user.id`, u.account_name as `user.account_name` FROM posts AS p JOIN users AS `u` ON p.user_id = u.id WHERE u.del_flg=0 ORDER by p.created_at desc, p.id ASC LIMIT 20"

	err := db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC LIMIT 30")
	// err := db.Select(&results, q)
	if err != nil {
		log.Print(err)
		return
	}

	for i := range results {
		results[i].User.AccountName = accountNameCache.getUserNameCache(results[i].UserID)
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	getIndexTemp.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT 20", user.ID)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	for i := range results {
		results[i].User = user
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID) //TODO:キャッシュ使う
	if err != nil {
		log.Print(err)
		return
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	getAccountNameTemp.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}
	// q := "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.id AS `user.id`, u.account_name AS `user.account_name` FROM posts AS p JOIN users as `u` ON p.user_id = u.id WHERE p.created_at <= ? AND u.del_flg=0 ORDER BY p.created_at DESC, p.id ASC limit 20"
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC LIMIT 30", t.Format(ISO8601Format))
	// err = db.Select(&results, q, t.Format(ISO8601Format))
	if err != nil {
		log.Print(err)
		return
	}

	for i := range results {
		results[i].User.AccountName = accountNameCache.getUserNameCache(results[i].UserID)
	}

	posts, err := makePosts(results, getCSRFToken(r), false)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostsTemp.Execute(w, posts)
}

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	q := "SELECT p.`id`, p.`user_id`, p.`body`, p.`mime`, p.`created_at`, u.id as `user.id`, u.account_name as `user.account_name` from posts as p join users as `u` on p.user_id = u.id where p.id = ? and u.del_flg=0;"
	// err = db.Select(&results, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	err = db.Select(&results, q, pid)
	if err != nil {
		log.Print(err)
		return
	}

	posts, err := makePosts(results, getCSRFToken(r), true)
	if err != nil {
		log.Print(err)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	getPostsIdTemp.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	pidStr := strconv.FormatInt(pid, 10)

	f, err := os.Create(imagesFolderPath + pidStr + "." + ext)
	if err != nil {
		log.Printf("failed to create file: %v", err)
		return
	}

	_, err = f.Write(filedata)
	if err != nil {
		log.Printf("failed to write file: %v", err)
		return
	}

	err = f.Close()
	if err != nil {
		log.Printf("failed to close file: %v", err)
	}

	http.Redirect(w, r, "/posts/"+pidStr, http.StatusFound)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	ext := chi.URLParam(r, "ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		w.Header().Set("Content-Type", post.Mime)
		_, err := w.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return
		}

		// ファイルを保存する
		f, err := os.Create(imagesFolderPath + pidStr + "." + ext)
		defer func() {
			err := f.Close()
			if err != nil {
				log.Printf("failed to close file: %v", err)
			}
		}()

		if err != nil {
			log.Printf("faild to create file: %v", err)
			return
		}
		_, err = f.Write(post.Imgdata)
		if err != nil {
			log.Printf("failed to write file: %v", err)
			return
		}

		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	result, err := db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}

	commentId, _ := result.LastInsertId()
	commentCache.updateCommentCache(postID, Comment{
		ID:        int(commentId),
		PostID:    postID,
		UserID:    me.ID,
		Comment:   r.FormValue("comment"),
		User:      me,
		CreatedAt: time.Now(),
	})

	commentCountCache.addCommentCountCache(postID, 1)

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	getAdminBannedTemp.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	for _, id := range r.Form["uid[]"] {
		db.Exec(query, 1, id)
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	//pprof
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	commentCache.Reset()
	commentCountCache.Reset()
	accountNameCache.Reset()

	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Get("/image/{id}.{ext}", getImage)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("../public")).ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
