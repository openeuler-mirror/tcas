# Trust Cluster Attestation Server(TCAS)

## build 
```shell
cd hack
bash release.sh buildimage

```

## deploy

```shell
mkdir /opt/tcas/
cp -a conf /opt/tcas
docker run  -p8081:8081 -v/opt/tcas/conf:/workplace/app/conf -v/opt/tcas/data:/workplace/encryptedData tcas:latest start 
```
