# The edge as a deployable artifact. Build from the repo root:
#   mvn -q -pl core,heimdall,sim install
#   docker build -f heimdall/Dockerfile -t bifrost/heimdall:dev .
FROM eclipse-temurin:17-jre
WORKDIR /opt/heimdall
COPY heimdall/target/bifrost-heimdall.jar app.jar

# The registry is MOUNTED, never baked: the governed model belongs to the site, and an image that
# carries a copy hides which copy is actually running - the same failure ENTERPRISE.md row 13 is
# about. There is deliberately no VOLUME line either; it would create an empty anonymous volume on
# a `docker run` without -v and turn a clear "policy.json missing" into a confusing empty mount.
ENV REGISTRY_PATH=/opt/heimdall/registry \
    POLICY_PATH=/opt/heimdall/registry/policy.json \
    HEALTH_PORT=9090

EXPOSE 9090

# start-period covers the ledger-trust checks and the first OPC-UA connect attempt. The edge now
# starts even when the plant is down, so an unhealthy container here means it is still down --
# which is exactly what the endpoint is meant to report.
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:9090/healthz || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
