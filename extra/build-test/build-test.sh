#!/bin/bash

# Simple shell script that compiles Meern with multiple flags.  This helps 
# hunt down compile time bugs. 
# 
# - Public release (10/04/2021) 

# --disable-tcmalloc

STANDARD="--disable-postgresql --disable-elasticsearch --disable-mysql --disable-bluedot --disable-geoip --enable-redis"
ALLFLAGS="--enable-postgresql --enable-elasticsearch --enable-mysql --enable-bluedot --enable-geoip --enable-redis"
NOFLAG="--disable-postgresql --disable-elasticsearch --disable-mysql --disable-bluedot --disable-geoip --disable-redis"

LOG="output.log" 

MAKE_FLAGS="-j7"

autoreconf -vfi

echo "**** STANDARD BUILD | NO FLAGS ****"
echo "**** STANDARD BUILD | NO FLAGS ****" >> $LOG

#make clean
#cd tools && make clean && cd ..

CFLAGS=-Wall ./configure

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
	exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ] 
	then
	echo "Error on standard build!";
	exit
	fi

echo "**** ALL FLAGS : $ALLFLAGS ****"
echo "**** ALL FLAGS : $ALLFLAGS ****" >> $LOG

make clean

CFLAGS=-Wall ./configure $ALLFLAGS

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

echo "****  NO FLAGS : $NOFLAG ****"
echo "****  NO FLAGS : $NOFLAG ****" >> $LOG

make clean

CFLAGS=-Wall ./configure $NOFLAG

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

echo "--------------------[ Rotating Through Flags ]--------------------"
echo "--------------------[ Rotating Through Flags ]--------------------" >> $LOG

for I in $STANDARD
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $ALLFLAGS
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $NOFLAGS
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

