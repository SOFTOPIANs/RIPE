# Makefile for RIPE
# @author John Wilander & Nick Nikiforakis

#Depending on how you test your system you may want to comment, or uncomment the following
#
## [CFLAGS settings]
# SAFESTACK
# CFLAGS=-fno-stack-protector -fsanitize=safe-stack #-fsanitize=cpi
# CPS
# CFLAGS=-fno-stack-protector -fsanitize=cpi -mllvm -CPS -fsanitize=safe-stack
# CPI
# CFLAGS=-fno-stack-protector -fsanitize=cpi -fsanitize=safe-stack
# CFI
CFLAGS=-fno-stack-protector -fsanitize=cfi -fvisibility=default -flto 
# STACK PROTECTOR
# CFLAGS=-fstack-protector-all
# NO STACK PROTECTOR
# CFLAGS=-fno-stack-protector
## [CC settings]
# CC=/usr/local/bin/clang_cpi
CC=/usr/local/cpi/bin/clang -w
# [basic]
# CC=gcc -w
all: ripe_attack_generator
simple: ripe_simple
simple2: ripe_simple2

clean:
	rm ./build/*

# ATTACK GENERATOR COMPILE
# ripe_attack_generator: ./bbb.c
	# ${CC} ${CFLAGS} ./bbb.c -m32 -o ./aaa
# ripe_attack_generator: ./source/bbb.c
	# ${CC} ${CFLAGS} ./source/bbb.c -m32 -o ./build/ripe_attack_generator 
ripe_attack_generator: ./source/ripe_attack_generator.c
	${CC} ${CFLAGS} ./source/ripe_attack_generator.c -m32 -o ./build/ripe_attack_generator 

ripe_simple: ./source/ripe_simple.c
	${CC} ${CFLAGS} ./source/ripe_simple.c -m32 -o ./build/ripe_simple

ripe_simple2: ./source/ripe_simple2.c
	${CC} ${CFLAGS} ./source/ripe_simple2.c -m32 -o ./build/ripe_simple2
