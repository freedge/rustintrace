FROM quay.io/centos/centos:stream9 as build
WORKDIR /src
RUN dnf install -y rust cargo libpcap libpcap-devel
COPY Cargo.toml /src/
COPY Cargo.lock /src/
COPY src /src/src
RUN cargo fetch
RUN cargo build --release

FROM quay.io/centos/centos:stream9-minimal
RUN microdnf --disablerepo=* --enablerepo=baseos install -y libpcap
COPY --from=build /src/target/release/rustintrace /rustintrace
ENTRYPOINT ["/rustintrace"]
