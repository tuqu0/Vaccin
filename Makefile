CC=gcc
EXEC=vaccin
PROJ=Vaccin
FILES= ./src/main.c ./src/utils.c ./src/vaccin.c
CFLAGS= -ggdb -O0 -Wall
LDFLAGS= -L ./lib/
LIBS= ./lib/libiniparser32bits.a
OBJS=$(FILES:.c=.o)
DIST= puydoyeux_vincent-vaccin

MyVirus: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o ./bin/$(EXEC) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./src/*.o
	rm -f ./bin/$(EXEC)
	
dist: clean
	mkdir ../$(DIST)
	cp -r ../$(PROJ)/*  ../$(DIST)
	rm -rf ../$(DIST).tar.gz 2>/dev/null
	tar cvfj ../$(DIST).tar.gz ../$(DIST) 
	rm -rf ../$(DIST)
