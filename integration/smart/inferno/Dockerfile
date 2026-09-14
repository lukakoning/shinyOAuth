FROM ruby:3.3.6@sha256:347edd0c70ee08d87de9f01b99de2f14a64cedb5d1bfb38457dfe8cd0bf113c5

WORKDIR /opt/inferno
RUN git init . && git remote add origin https://github.com/inferno-framework/smart-app-launch-test-kit.git \
    && git fetch --depth 1 origin 980e54e4ed632b28267d797013399a8588772174 \
    && git checkout --detach FETCH_HEAD
RUN gem install bundler --version 2.5.3 --no-document \
    && bundle _2.5.3_ config set frozen true \
    && bundle _2.5.3_ install --jobs 4
COPY simulator.patch /tmp/simulator.patch
RUN git apply --check /tmp/simulator.patch && git apply /tmp/simulator.patch
ENV APP_ENV=production
EXPOSE 4567
CMD ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:4567"]
