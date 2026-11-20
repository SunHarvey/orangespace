FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium chromium-sandbox dbus-daemon dbus-x11 \
        lxqt-session lxqt-panel lxqt-config lxqt-themes breeze-icon-theme qt6-svg-plugins pcmanfm-qt openbox xcompmgr \
        xdg-user-dirs xdg-utils x11-utils fonts-dejavu fonts-noto-cjk \
        fcitx5 fcitx5-chinese-addons fcitx5-frontend-gtk3 fcitx5-frontend-qt6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 desktop \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh desktop

COPY desktop-session /usr/local/bin/desktop-session
COPY startup /usr/local/bin/startup
COPY desktop-ready /usr/local/bin/desktop-ready
RUN chmod 0755 /usr/local/bin/desktop-session /usr/local/bin/startup /usr/local/bin/desktop-ready
ENV HOME=/home/desktop DISPLAY=:0 XAUTHORITY=/tmp/.X11-unix/Xauthority \
    XDG_RUNTIME_DIR=/run/user/1000 XDG_CURRENT_DESKTOP=LXQt \
    QT_XCB_NO_MITSHM=1 QT_XCB_GL_INTEGRATION=none QT_QUICK_BACKEND=software \
    QT_QPA_PLATFORM=xcb GTK_IM_MODULE=fcitx QT_IM_MODULE=fcitx \
    XMODIFIERS=@im=fcitx LANG=C.UTF-8
USER 1000:1000
WORKDIR /home/desktop
ENTRYPOINT ["/usr/local/bin/startup"]
