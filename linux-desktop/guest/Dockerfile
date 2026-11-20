FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium chromium-sandbox dbus-daemon dbus-x11 locales \
        lxqt-session lxqt-panel lxqt-config lxqt-themes breeze-icon-theme qt6-svg-plugins pcmanfm-qt openbox xcompmgr \
        qterminal xdg-user-dirs xdg-utils x11-utils fonts-dejavu fonts-noto-cjk fonts-noto-color-emoji \
        fcitx5 fcitx5-chinese-addons fcitx5-frontend-gtk3 fcitx5-frontend-gtk4 fcitx5-frontend-qt6 \
    && sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 desktop \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh desktop

# Pinyin is on from the start and left Shift toggles Chinese/English: Windows
# input methods never reach a Linux window, and Ctrl+Space is often taken by
# the client OS (macOS input switching, Windows IME).
COPY fcitx5-profile /etc/xdg/fcitx5/profile
COPY fcitx5-config /etc/xdg/fcitx5/config
COPY desktop-session /usr/local/bin/desktop-session
COPY startup /usr/local/bin/startup
COPY desktop-ready /usr/local/bin/desktop-ready
RUN chmod 0755 /usr/local/bin/desktop-session /usr/local/bin/startup /usr/local/bin/desktop-ready \
    && chmod 0644 /etc/xdg/fcitx5/profile /etc/xdg/fcitx5/config
# DISPLAY and XAUTHORITY are set per sandbox when the container is created.
ENV HOME=/home/desktop XDG_RUNTIME_DIR=/run/user/1000 XDG_CURRENT_DESKTOP=LXQt \
    QT_XCB_NO_MITSHM=1 QT_XCB_GL_INTEGRATION=none QT_QUICK_BACKEND=software \
    QT_QPA_PLATFORM=xcb GTK_IM_MODULE=fcitx QT_IM_MODULE=fcitx SDL_IM_MODULE=fcitx \
    XMODIFIERS=@im=fcitx LANG=zh_CN.UTF-8 LC_ALL=zh_CN.UTF-8
USER 1000:1000
WORKDIR /home/desktop
ENTRYPOINT ["/usr/local/bin/startup"]
