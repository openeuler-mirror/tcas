#!/bin/bash
set -o errexit
set -x
BASEDIR="$( cd "$( dirname "$0"  )" && pwd  )"
VERSION=$(git tag -l --points-at HEAD)
buildTime=$(date +%F-%H)
git_commit=$(git log -n 1 --pretty --format=%h)
DOCKER_PATH=./hack/docker

if [ -z "$VERSION" ];then
    VERSION=latest
fi
release_desc=${VERSION}-${git_commit}-${buildTime}

function build::image() {
   PROXY=$1
   PUSHTOHUB=$2
   HUB_ADDR=$3
   HUB_REP=$4
   HUB_USER_NAME=$5
   HUB_PASSWD=$6
	 echo "---> Build Image"

   cd $BASEDIR/../
	 HOME=`pwd`
   rm -rf $BASEDIR/../../docker-release
   cp -a $BASEDIR/../hack/docker $BASEDIR/../../docker-release
   cd $BASEDIR/../../docker-release
	 cp -r $BASEDIR/../conf .
	 cp -r /usr/share/zoneinfo .

	 mkdir tmp
   cp -a $BASEDIR/../* tmp
	 docker build --build-arg https_proxy=$PROXY --build-arg http_proxy=$PROXY --build-arg VERSION=$release_desc --no-cache -t tcas:${VERSION} -f Dockerfile .

#    if [[ x$PUSHTOHUB  != x ]];then
#        docker tag secret_prov_server $HUB_ADDR/$HUB_REP/tcas:${VERSION}
#        docker login -u $HUB_USER_NAME -p $HUB_PASSWD  $HUB_ADDR
#        docker push $HUB_REP/tcas:${VERSION}
#    fi
	 cd $HOME
}
case $1 in
	buildimage)
		build::image $2 $3 $4 $5 $6 $7
	;;
esac