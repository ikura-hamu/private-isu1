include server_id.sh

# SERVER_ID  server_id.shで定義

PROJECT_ROOT:=/home/isucon/ #/home/isuconを想定
APP_DIR:=$(PROJECT_ROOT)/webapp/golang

USER_NAME:=isucon

GIT_URL:=git@github.com:ikura-hamu/private-isu1.git

DB_SERVICE:=mysql
APP_SERVICE:=isu-go
APP_BIN:=$(APP_DIR)/app

DB_CONF:=/etc/mysql
NGINX_CONF:=/etc/nginx
LOCAL_DB_CONF:=$(PROJECT_ROOT)/$(SERVER_ID)/etc/mysql
LOCAL_NGINX_CONF:=$(PROJECT_ROOT)/$(SERVER_ID)/etc/nginx
ALP_CONF:=$(PROJECT_ROOT)/tools/alp/alp_conf.yml

SLOW_LOG_FILE:=/var/log/mysql/slow.log
ACCESS_LOG_FILE:=/var/log/nginx/access.log

SLOW_LOGS:=/tmp/slow
ALP_LOGS:=/tmp/alp

WEBHOOK_URL:=https://discord.com/api/webhooks/1103191010445635654/am8zeNTVVunqtfrLScK2wrBbi7fabhYzIKSbj1h-HBo6-mdMFrPkorithMj9jfF-YBQR

# 使うやつ

# 最初
.PHONY: setup
setup: install-tools git-setup1

#====================#
# ローカル  					#
#====================#

#====================#
# サーバー内					#
#====================#

# SERVER_IDを指定
.PHONY: set-as-%
set-as-%:
	touch server_id.sh
	@echo "SERVER_ID=$(@:set-as-%=%)" >> server_id.sh

# SERVER_IDが設定されているか確認
.PHONY: check-server-id
check-server-id:
ifdef SERVER_ID
		@echo "SERVER_ID is set: $(SERVER_ID)"
else
		@echo "SERVER_ID is not set"
		exit 1
endif

# ベンチマーク前
.PHONY: before-bench
before-bench: set-db-conf	set-nginx-conf rm-slow-log	rm-access-log	restart

# ベンチマーク後に計測結果送信
.PHONY: after-bench
after-bench: slow	alp pprof-check

# pprofで記録する
.PHONY: pprof-record
pprof-record:
	go tool pprof -seconds=60 http://localhost:6060/debug/pprof/profile

# pprofで確認する
.PHONY: pprof-check
pprof-check:
	$(eval latest := $(shell ls -rt pprof/ | tail -n 1))
	go tool pprof -http=localhost:8090 pprof/$(latest)

# スロークエリ(pt-query-digest)
.PHONY: slow
slow:
	-@ mkdir $(SLOW_LOGS)
	sudo pt-query-digest --type slowlog $(SLOW_LOG_FILE) > $(SLOW_LOGS)/temp.txt
	-@curl -X POST -F txt=@$(SLOW_LOGS)/temp.txt $(WEBHOOK_URL) -s -o /den/null
	mv $(SLOW_LOGS)/temp.txt $(SLOW_LOGS)/$(TZ=JST-9 date +%y%m%d_%H%M).txt

# アクセスログ(alp)
.PHONY: alp
alp:
	-@ mkdir $(ALP_LOGS) $(ALP_LOGS)/dump
	sudo alp ltsv --reverse --limit=30 --file=$(ACCESS_LOG_FILE) --config=$(ALP_CONF) --dump=$(ALP_LOGS)/dump/$(shell TZ=JST-9 date +%y%m%d_%H%M).dump > $(ALP_LOGS)/temp.txt
	-@curl -X POST -F txt=@$(ALP_LOGS)/temp.txt $(WEBHOOK_URL) -s -o /dev/null
	mv $(ALP_LOGS)/temp.txt $(ALP_LOGS)/$(shell TZ=JST-9 date +%y%m%d_%H%M).txt

.PHONY: alp-diff
alp-diff:
	$(eval latest := $(shell ls -rt $(ALP_LOGS)/dump | tail -n 1))
	$(eval before := $(shell ls -rt $(ALP_LOGS)/dump | tail -n 2 | head -n 1))
	sudo alp diff $(ALP_LOGS)/dump/$(before) $(ALP_LOGS)/dump/$(latest) --reverse --limit=30 --config=$(ALP_CONF) > $(ALP_LOGS)/diff.txt
	-@curl -X POST -F txt=@$(ALP_LOGS)/diff.txt $(WEBHOOK_URL) -s -o /dev/null

#====================#
# 各コマンドの構成要素 #
#====================#
.PHONY: install-tools
install-tools:
	sudo apt update
	sudo apt upgrade
	sudo apt install -y git unzip dstat tree
	sudo apt-get install -y percona-toolkit

#	uname -m でCPUのアーキテクチャを調べる
#	amdならそのまま
	wget https://github.com/tkuchiki/alp/releases/download/v1.0.12/alp_linux_amd64.zip
	unzip alp_linux_amd64.zip
	install ./alp /usr/local/bin/alp
#armならこっちにする
#	wget https://github.com/tkuchiki/alp/releases/download/v1.0.12/alp_linux_arm64.zip
# unzip alp_linux_arm64.zip
	-@rm alp alp_linux_amd64.zip alp_linux_arm64.zip

.PHONY: git-setup1
git-setup1:
	git config --global user.email "server@example.com"
	git config --global user.name "server"

	git init
	git add 

	touch .gitignore
	echo .ssh/* >> .gitignore
	echo server_id.sh >> .gitignore

.PHONY: git-setup2
git-setup2:
	git init
	git add .
	git commit -m "init"
	git branch -m main

	git remote add origin $(GIT_URL)
	git pull origin main

.PHONY: get-db-conf
get-db-conf: 
	sudo cp -r $(DB_CONF)/* $(LOCAL_DB_CONF)

.PHONY: get-nginx-conf
get-nginx-conf:
	sudo cp -r $(NGINX_CONF)/* $(LOCAL_NGINX_CONF)

.PHONY: set-db-conf
set-db-conf:
	sudo cp -r $(LOCAL_DB_CONF)/* $(DB_CONF)

.PHONY: set-nginx-conf
set-nginx-conf:
	sudo cp -r $(LOCAL_NGINX_CONF)/* $(NGINX_CONF)

.PHONY: rm-slow-log
rm-slow-log:
	sudo truncate $(SLOW_LOG_FILE) -s 0 -c

.PHONY: rm-access-log
rm-access-log:
	sudo truncate $(ACCESS_LOG_FILE) -s 0 -c

.PHONY: restart
restart:
	sudo systemctl restart $(DB_SERVICE)
	sudo systemctl restart nginx
	sudo systemctl restart $(APP_SERVICE)

.PHONY: build
build:
	cd $(APP_DIR) && go build -o $(APP_BIN)