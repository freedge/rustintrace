FROM quay.io/centos/centos:stream9 as build
WORKDIR /src
RUN dnf install -y rust cargo libpcap libpcap-devel
COPY Cargo.toml /src/
COPY Cargo.lock /src/
COPY src /src/src
RUN cargo build && cargo test
RUN cargo build --release

FROM quay.io/centos/centos:stream9-minimal
LABEL io.containers.capabilities=net_admin,net_raw
RUN rm /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-Extras && \
    microdnf --disablerepo=* --enablerepo=baseos install -y libpcap && \
    microdnf clean all
COPY --from=build /src/target/release/rustintrace /rustintrace
ENTRYPOINT ["/rustintrace"]
