# vim: set noexpandtab:
# 
# Flow spec NLRI encode 
# 
# Aniruddha. A (aniruddha.a@gmail.com)
#  

CC = gcc
CFLAGS = -Wall -g -ggdb #-O2  
OBJECTS = flospec.o utils.o encode.o token.o debug.o
#LINKOPTS = -lefence
all : flospec

flospec : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LINKOPTS) -o $@ 

%.o : %.c %.h
	$(CC) $(CFLAGS) -c $<
clean:
	@rm -f $(OBJECTS) flospec flospec.tgz
pkg:
	@tar zcvf flospec.tgz Makefile \
	   	  README* \
		  TODO \
		  *.[ch] 
