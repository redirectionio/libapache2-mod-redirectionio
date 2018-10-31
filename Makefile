# Source files. mod_auth_mellon.c must be the first file.
SRC=src/mod_redirectionio.c \
	src/json.c \
	src/redirectionio_protocol.c

all: src/mod_redirectionio.la

src/mod_redirectionio.la: $(SRC) src/mod_redirectionio.h src/json.h src/redirectionio_protocol.h
	/usr/bin/apxs2 -Wc,"-std=c99  " -Wl,"" -lm -Wc,-Wall -Wc,-g -c $(SRC)

.PHONY:	install
install: src/mod_redirectionio.la
	/usr/bin/apxs2 -i -n redirectionio src/mod_redirectionio.la

.PHONY:	clean
clean:
	rm -f src/mod_redirectionio.la
	rm -f $(SRC:%.c=%.o)
	rm -f $(SRC:%.c=%.lo)
	rm -f $(SRC:%.c=%.slo)
	rm -rf .libs/
