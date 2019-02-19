# Source files. mod_auth_mellon.c must be the first file.
SRC=src/mod_redirectionio.c \
	src/json.c \
	src/redirectionio_protocol.c

PROXY_VERSION ?= libapache2-mod-redirectionio:dev

all: src/mod_redirectionio.la

src/mod_redirectionio.la: $(SRC) src/mod_redirectionio.h src/json.h src/redirectionio_protocol.h
	apxs -Wc,"-std=c99 -DPROXY_VERSION=$(PROXY_VERSION)  " -Wl,"" -lm -Wc,-Wall -Wc,-g -c $(SRC)

.PHONY:	install
install: src/mod_redirectionio.la
	apxs -i -n redirectionio src/mod_redirectionio.la

.PHONY:	clean
clean:
	rm -f src/mod_redirectionio.la
	rm -f $(SRC:%.c=%.o)
	rm -f $(SRC:%.c=%.lo)
	rm -f $(SRC:%.c=%.slo)
	rm -rf .libs/
