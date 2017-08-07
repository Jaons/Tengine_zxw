
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile
	$(MAKE) -f objs/Makefile manpage

test:
	$(MAKE) -f objs/Makefile test

install:
	$(MAKE) -f objs/Makefile install

dso_install:
	$(MAKE) -f objs/Makefile dso_install

upgrade:
	/opt/apps/nginx/sbin/nginx -t

	kill -USR2 `cat /opt/apps/nginx/logs/nginx.pid`
	sleep 1
	test -f /opt/apps/nginx/logs/nginx.pid.oldbin

	kill -QUIT `cat /opt/apps/nginx/logs/nginx.pid.oldbin`
