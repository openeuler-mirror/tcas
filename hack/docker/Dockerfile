FROM ubuntu:20.04 as virtcca

#use tsinghua sources for accelerate in CN
RUN sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    sed -i s@/security.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    apt-get clean

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       git \
       cmake \
       libssl-dev \
       g++

RUN  git clone https://github.com/laurencelundblade/QCBOR.git -b v1.2 /QCBOR \
     && cd /QCBOR \
     && make \
     && make install

RUN  git clone https://github.com/laurencelundblade/t_cose.git -b v1.1.2 /t_cose \
     && cd /t_cose \
     && cmake -S . -B build \
     && cmake --build build \
     && cmake --install build


RUN git clone -b tcas https://gitee.com/nanhu-lab/virtCCA_sdk.git/  /virtCCA_sdk \
    && cd /virtCCA_sdk/attestation/sdk \
    && cmake -S . -B build \
    && cmake --build build \
    && cmake --install build \
    && cd /virtCCA_sdk/attestation/samples \
    && cmake -S . -B build \
    && cmake --build build -v

FROM ubuntu:20.04 as tcas

#use tsinghua sources for accelerate in CN
RUN sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    sed -i s@/security.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    apt-get clean

RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       wget \
       pkg-config \
       unzip \
       build-essential \
       git \
       libssl-dev

COPY tmp /tcas

RUN wget --progress=bar:force -c https://dl.google.com/go/go1.22.2.linux-amd64.tar.gz -O - | tar -xz -C /usr/local

#RUN git clone https://github.com/guanzhi/GmSSL.git \
#    && cd GmSSL \
#    && git checkout GmSSL-v2 \
#    && git checkout 5b904768 \
#    && sed -i "s/qw\/glob/qw\/:glob/g" Configure \
#    && sed -i "s/qw\/glob/qw\/:glob/g" test/build.info \
#    && ./config --prefix=/opt/gmssl \
#    && make install
COPY --from=virtcca /t_cose/build/libt_cose.a /usr/local/lib/
COPY --from=virtcca /t_cose/inc/t_cose/ /usr/local/include/t_cose
COPY --from=virtcca /QCBOR/libqcbor.a /usr/local/lib/
COPY --from=virtcca /QCBOR/inc/qcbor /usr/local/include/qcbor
COPY --from=virtcca /virtCCA_sdk/attestation/samples/build/libvccaverifier.so /lib/x86_64-linux-gnu/

RUN cd /tcas \
    && PATH=$PATH:/usr/local/go/bin \
       GOPROXY=https://goproxy.cn,direct \
       go build -ldflags "-w -s -X tcas/version.version=${VERSION}" -o tcas


FROM ubuntu:20.04
#use tsinghua sources for accelerate in CN
RUN sed -i s@/archive.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    sed -i s@/security.ubuntu.com/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list && \
    apt-get clean
RUN apt-get update \
    && env DEBIAN_FRONTEND=noninteractive apt-get install -y \
       curl \
       wget \
       libssl-dev
RUN mkdir -p  /usr/share/zoneinfo/
COPY zoneinfo /usr/share/zoneinfo
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

RUN mkdir -p  /usr/share/zoneinfo/ \
    && mkdir -p /workplace/app/certs \
    && mkdir -p /workplace/app/ca \
    && mkdir -p /workplace/app/logs \
    && mkdir -p /workplace/app/conf \
    && mkdir -p /workplace/app/views

ARG VERSION=latest
RUN echo $VERSION > /VERSION
COPY --from=virtcca /t_cose/build/libt_cose.a /usr/local/lib/
COPY --from=virtcca /QCBOR/libqcbor.a /usr/local/lib/
COPY --from=virtcca /virtCCA_sdk/attestation/samples/build/libvccaverifier.so /lib/x86_64-linux-gnu/
#COPY --from=tcas /opt/gmssl /opt/gmssl
COPY --from=tcas /tcas/tcas /workplace/app/tcas
COPY conf/ /workplace/app/conf

WORKDIR /workplace/app
ENTRYPOINT ["./tcas"]

