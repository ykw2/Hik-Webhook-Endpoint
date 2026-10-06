(function () {
  var grid = document.getElementById("device-grid");
  var feed = document.getElementById("feed");
  if (!grid || !feed) return;

  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";
  var latest = Number(feed.getAttribute("data-latest") || "0");
  var deviceSig = "";

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
    if (sig === deviceSig) {
      var cards = grid.querySelectorAll(".device");
      devices.forEach(function (device, index) {
        var lines = cards[index] && cards[index].querySelectorAll("small");
        if (!lines || !lines[1]) return;
        lines[1].textContent =
          (device.status_label || "") + (device.last_seen ? " · " + device.last_seen : "");
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
        return (
          '<article class="device ' +
          (online ? "online" : "offline") +
          '"><span class="status-icon" role="img" aria-label="' +
          esc(device.status_label) +
          '">' +
          icon(online) +
          '</span><div class="device-copy"><strong>' +
          esc(device.name) +
          "</strong><small>" +
          esc(device.ip || "未知 IP") +
          (device.mac ? " · " + esc(device.mac) : "") +
          "</small><small>" +
          esc(device.status_label) +
          (device.last_seen ? " · " + esc(device.last_seen) : "") +
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
      var res = await fetch("/live", {
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

  setInterval(tick, 2000);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) tick();
  });
})();
