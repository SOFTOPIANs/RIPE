# Makefile for RIPE
# @author John Wilander & Nick Nikiforakis

#Depending on how you test your system you may want to comment, or uncomment the following
#
## [CFLAGS settings]
# SAFESTACK
# CFLAGS=-fno-stack-protector -fsanitize=safe-stack -w
# CPS
# CFLAGS=-fno-stack-protector -fsanitize=cpi -mllvm -CPS -w
# CPI
CFLAGS=-fno-stack-protector -fsanitize=cpi -mllvm -CPI -w
# STACK PROTECTOR
# CFLAGS=-fstack-protector-all
# NO STACK PROTECTOR
# CFLAGS=-fno-stack-protector
## [CC settings]
CC=/usr/local/bin/clang_cpi
# [basic]
# CC=gcc
all: ripe_attack_generator

clean:
	rm ./build/*

# ATTACK GENERATOR COMPILE
# ripe_attack_generator: ./source/ripe_attack_generator.c
# 	${CC} ${CFLAGS} ./source/ripe_attack_generator.c -m32 -o ./build/ripe_attack_generator 
# ripe_attack_generator: ./bbb.c
	# ${CC} ${CFLAGS} ./bbb.c -m32 -o ./aaa
ripe_attack_generator: ./source/bbb.c
	${CC} ${CFLAGS} ./source/bbb.c -m32 -o ./build/ripe_attack_generator 

