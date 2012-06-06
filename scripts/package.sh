#!/bin/bash

BY=`whoami`
CWD=`pwd`
SCM=`git remote show origin |grep Fetch\ URL |awk '{ print $3 }'`
TIMESTAMP=`date +%Y-%m-%d`
VERSION=`git tag |tail -n1`
WORK=/tmp/veripy-build-`date +%Y%m%d%H%M%S`

echo "** Preparing veripy v$VERSION."
mkdir $WORK

echo "** Fetching a fresh copy from SCM..."
git clone $SCM $WORK/$VERSION > /dev/null 2>&1

cd $WORK/$VERSION
echo "** Switching to tag $VERSION..."
git checkout $VERSION > /dev/null 2>&1

echo "** Removing files we will not ship..."
echo "   .git/*"
rm -rf .git
rm .gitignore
echo "   Makefile"
rm Makefile
echo "   scripts/*"
rm -rf scripts

echo "** Creating the VERSION file..."
echo "veripy v$VERSION - $TIMESTAMP ($BY)" > VERSION

echo "** Preparing a ZIP archive..."
zip -r "$CWD/veripy-$VERSION.zip" * > /dev/null 2>&1

cd "$CWD"
echo "** Calculating MD5 checksum..."
MD5=`md5sum veripy-$VERSION.zip| awk '{ print $1 }'`

echo "** Cleaning up..."
rm -rf $WORK

echo "** Packaged as: veripy-$VERSION.zip (md5sum $MD5)"
