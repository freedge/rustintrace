FROM registry.access.redhat.com/ubi9:latest as build
WORKDIR /src
RUN dnf install -y rust cargo libpcap libpcap-devel
COPY Cargo.toml /src/
COPY Cargo.lock /src/
COPY src /src/src
RUN cargo update
RUN cargo build --release

FROM registry.access.redhat.com/ubi9-minimal:latest
RUN microdnf --disablerepo=* --enablerepo=ubi-9-baseos-rpms install -y libpcap
COPY --from=build /src/target/release/rustintrace /rustintrace
ENTRYPOINT ["/rustintrace"]
