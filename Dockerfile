# Single image, single pipeline slot (project 03). Backend-only service:
# login/register pages are server-rendered from the jar.
# Build args are stamped by the shared pipeline (sebastiancardona-dev/workflows).

FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /build
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -q -B dependency:go-offline
COPY src src
# tests run in CI; the image build must be reproducible and fast
RUN ./mvnw -q -B package -DskipTests

FROM eclipse-temurin:21-jre-alpine
ARG VERSION=dev
ARG GIT_SHA=unknown
ARG BUILD_TIME=unknown
# surfaces on /info via Spring's env info contributor (ecosystem contract)
ENV INFO_APP_VERSION=$VERSION \
    INFO_APP_GIT_SHA=$GIT_SHA \
    INFO_APP_BUILD_TIME=$BUILD_TIME
RUN adduser -D -u 10001 auth
USER 10001
WORKDIR /app
COPY --from=build /build/target/auth-service-*.jar app.jar
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=60s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
