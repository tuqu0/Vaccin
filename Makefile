CC=gcc
EXEC=MyWorm
FILES= ./src/main.c ./src/utils.c
CFLAGS= -ggdb -O0 -Wall
LIBS=
OBJS=$(FILES:.c=.o)
DIST= puydoyeux_vincent-MyWorm

MyVirus: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o ./bin/$(EXEC) $(OBJS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./src/*.o
	rm -f ./bin/$(EXEC)
	rm -f $(EXEC) 2>/dev/null
	rm -f ./src/$(EXEC)
	rm -f ./include/$(EXEC)
	rm -f ./.git/$(EXEC)
	
dist: clean
	mkdir ../$(DIST)
	cp -r ../$(EXEC)/*  ../$(DIST)
	rm -rf ../$(DIST).tar.gz 2>/dev/null
	tar cvfj ../$(DIST).tar.gz ../$(DIST) 
	rm -rf ../$(DIST)
