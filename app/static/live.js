(function () {
  var grid = document.getElementById("device-grid");
  var feed = document.getElementById("feed");
  if (!grid || !feed) return;

  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";
  var latest = Number(feed.getAttribute("data-latest") || "0");
  var deviceSig = "";
  var seen = {};

  grid.querySelectorAll(".device").forEach(function (card) {
    seen[card.getAttribute("data-id")] = card.getAttribute("data-seen") || "";
  });

  function bounce(deviceId) {
    var icon = grid.querySelector('.device[data-id="' + deviceId + '"] .status-icon');
    if (!icon) return;
    icon.classList.remove("beat");
    void icon.offsetWidth;
    icon.classList.add("beat");
  }

  function esc(value) {
    return String(value || "").replace(/[&<>"']/g, function (char) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[char];
    });
  }

  function icon(online) {
    if (online) {
      return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9.2 16.2 5.4 12.4l1.4-1.4 2.4 2.4 6.9-6.9 1.4 1.4z"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M7 11h10v2H7z"/></svg>';
  }

  function renderDevices(devices) {
    var sig = JSON.stringify(
      devices.map(function (device) {
        return [device.id, device.online, device.name, device.ip, device.mac, device.status_label];
      })
    );
    var firstPaint = deviceSig === "";
    if (sig === deviceSig) {
      devices.forEach(function (device) {
        var previous = seen[device.id];
        seen[device.id] = device.last_seen || "";
        if (device.online && previous !== device.last_seen) bounce(device.id);
        var stamp = grid.querySelector('.device[data-id="' + device.id + '"] .seen');
        if (stamp) stamp.textContent = device.last_clock || "";
        var card = grid.querySelector('.device[data-id="' + device.id + '"]');
        if (card) card.setAttribute("data-seen", device.last_seen || "");
      });
      return;
    }
    deviceSig = sig;
    if (!devices.length) {
      grid.innerHTML = '<p class="empty device-empty">未收到任何裝置心跳。</p>';
      return;
    }
    grid.innerHTML = devices
      .map(function (device) {
        var online = !!device.online;
        var remove = online
          ? ""
          : '<form method="post" action="/devices/' +
            Number(device.id) +
            '/remove"><input type="hidden" name="csrf" value="' +
            esc(csrf) +
            '"><button class="btn small danger" type="submit">移除</button></form>';
        var jumped = !firstPaint && online && seen[device.id] !== (device.last_seen || "");
        seen[device.id] = device.last_seen || "";
        return (
          '<article class="device ' +
          (online ? "online" : "offline") +
          '" data-id="' +
          Number(device.id) +
          '" data-seen="' +
          esc(device.last_seen) +
          '"><span class="status-icon' +
          (jumped ? " beat" : "") +
          '" role="img" aria-label="' +
          esc(device.status_label) +
          '">' +
          icon(online) +
          '</span><div class="device-copy"><strong>' +
          esc(device.ip || "未知 IP") +
          "</strong><small>" +
          esc(device.status_label) +
          (device.last_clock ? ' · <span class="seen">' + esc(device.last_clock) + "</span>" : "") +
          "</small></div>" +
          remove +
          "</article>"
        );
      })
      .join("");
  }

  async function tick() {
    if (document.hidden) return;
    try {
      var liveUrl = new URL("/live", location.origin);
      var currentQuery = new URL(location.href).searchParams.get("q");
      if (currentQuery) liveUrl.searchParams.set("q", currentQuery);
      var res = await fetch(liveUrl, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (res.status === 401) {
        location.href = "/";
        return;
      }
      if (!res.ok) return;
      var data = await res.json();
      renderDevices(data.devices || []);
      refreshAgo();
      ["today", "queued", "sent", "failed"].forEach(function (key) {
        var node = document.getElementById("stat-" + key);
        if (node && data.stats) node.textContent = data.stats[key];
      });
      var clearForm = document.getElementById("clear-events");
      if (clearForm && data.stats) clearForm.hidden = !data.stats.total;
      if (Number(data.latest_id) !== latest) {
        if (document.activeElement && document.activeElement.closest("form.filters")) return;
        var url = new URL("/events/feed", location.origin);
        var current = new URL(location.href);
        ["q", "status", "page"].forEach(function (key) {
          var value = current.searchParams.get(key);
          if (value) url.searchParams.set(key, value);
        });
        var html = await fetch(url, { headers: { Accept: "text/html" }, cache: "no-store" });
        if (!html.ok) return;
        latest = Number(data.latest_id);
        feed.setAttribute("data-latest", String(latest));
        feed.innerHTML = await html.text();
      }
    } catch (err) {
      return;
    }
  }

  function refreshAgo() {
    document.querySelectorAll(".plate[data-at]").forEach(function (plate) {
      var then = new Date(plate.getAttribute("data-at"));
      if (isNaN(then.getTime())) return;
      var seconds = Math.floor((Date.now() - then.getTime()) / 1000);
      var label = "剛剛";
      if (seconds >= 60) {
        var minutes = Math.floor(seconds / 60);
        if (minutes < 60) label = minutes + "分鐘";
        else {
          var hours = Math.floor(minutes / 60);
          if (hours < 24) label = hours + "小時";
          else {
            var days = Math.floor(hours / 24);
            label = days === 1 ? "昨天" : days < 30 ? days + "日" : "";
          }
        }
      }
      var node = plate.querySelector(".ago");
      if (label && node && node.textContent !== label) node.textContent = label;
    });
  }

  setInterval(tick, 2000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) tick();
  });
})();
