FROM quay.io/centos/centos:stream9 as build
WORKDIR /src
RUN dnf install -y rust cargo libpcap libpcap-devel
# we go the extra step and install serde from the rpm...
# Probably not worth it
RUN dnf install -y 'dnf-command(config-manager)' &&  \
    dnf config-manager --set-enabled crb &&  \
    dnf install -y epel-release epel-next-release && \
    dnf install -y rust-serde-devel-1.0.185 && \
    mkdir -p /.cargo/
COPY config.toml.centos /.cargo/config.toml
COPY Cargo.toml /src/
COPY Cargo.lock /src/
COPY src /src/src
RUN cargo build && cargo test
RUN cargo build --release

FROM quay.io/centos/centos:stream9-minimal
RUN rm /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-Extras && \
    microdnf --disablerepo=* --enablerepo=baseos install -y libpcap && \
    microdnf clean all
COPY --from=build /src/target/release/rustintrace /rustintrace
ENTRYPOINT ["/rustintrace"]
