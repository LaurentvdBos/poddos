CFLAGS = -g -O2 -Wall
LDLIBS = -lssl -lcrypto -lz -lzstd

poddos: poddos.o http.o inflate.o truncate.o chunked.o pull.o json.o untar.o layer.o net.o dhcp.o prune.o zstd.o

.PHONY: all clean install uninstall
all: poddos
clean:
	-rm *.o
	-rm poddos
install: poddos poddos@.service poddos.1
	install poddos /usr/local/bin/
	setcap cap_net_admin+eip /usr/local/bin/poddos
	install --mode=644 --compare poddos@.service /etc/systemd/user/
	install --mode=644 poddos.1 /usr/local/share/man/man1/
uninstall:
	-rm /usr/local/bin/poddos
	-rm /etc/systemd/user/poddos@.service
	-rm /usr/local/share/man/man1/poddos.1
