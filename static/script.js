// script.js — NetWatch Frontend

// ── STATE ─────────────────────────────────────
let activeFilters  = { protocol: "ALL", src_ip: "", dst_ip: "" };
let packetInterval = null;
let lastSeenId     = 0;
let allPackets     = [];
const MAX_ROWS     = 500;

// ── XSS PROTECTION ────────────────────────────
function esc(str) {
    return String(str)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")
        .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── UPDATE ALL COUNTERS & STATS ───────────────
// Single function that updates CAPTURED, DISPLAYED, BYTES, and all stats.
// Called after every change to allPackets or activeFilters.
// CAPTURED = total packets in cache (all protocols, no filter)
// DISPLAYED = packets matching current filter
function updateUI(totalCaptured) {
    const filtered = filterLocally(allPackets);
    const stats    = calcStats(filtered);

    document.getElementById("hCaptured").textContent   = totalCaptured !== undefined
                                                         ? totalCaptured
                                                         : allPackets.length;
    document.getElementById("hDisplayed").textContent  = filtered.length;
    document.getElementById("packetCount").textContent = (totalCaptured !== undefined
                                                         ? totalCaptured
                                                         : allPackets.length) + " packets";
    renderStats(stats);
}

// ── START ─────────────────────────────────────
function startMonitoring() {
    lastSeenId = 0;
    allPackets = [];
    clearTable();

    document.getElementById("hCaptured").textContent   = 0;
    document.getElementById("hDisplayed").textContent  = 0;
    document.getElementById("hBytes").textContent      = 0;
    document.getElementById("packetCount").textContent = "0 packets";
    renderStats(calcStats([]));

    fetch("/start", { method: "POST" })
        .then(r => r.json())
        .then(data => {
            if (data.status !== "started") return;
            document.getElementById("btnStart").disabled = true;
            document.getElementById("btnStop").disabled  = false;
            document.getElementById("statusText").textContent = "MONITORING";
            document.getElementById("statusDot").classList.add("active");
            packetInterval = setInterval(fetchPackets, 1000);
            fetchPackets();
        });
}

// ── STOP ──────────────────────────────────────
function stopMonitoring() {
    fetch("/stop", { method: "POST" })
        .then(r => r.json())
        .then(data => {
            if (data.status !== "stopped") return;
            document.getElementById("btnStart").disabled = false;
            document.getElementById("btnStop").disabled  = true;
            document.getElementById("statusText").textContent = "STOPPED";
            document.getElementById("statusDot").classList.remove("active");
            clearInterval(packetInterval);
            updateUI();
        });
}

// ── FETCH PACKETS ─────────────────────────────
function fetchPackets() {
    const params = new URLSearchParams({
        protocol: "ALL",
        src_ip:   "",
        dst_ip:   "",
        since_id: lastSeenId
    });

    fetch("/packets?" + params)
        .then(r => r.json())
        .then(data => {
            if (data.packets && data.packets.length > 0) {
                allPackets = allPackets.concat(data.packets);
                if (allPackets.length > 5000) allPackets = allPackets.slice(-5000);
                lastSeenId = Math.max(...data.packets.map(p => p.id));

                const toShow = filterLocally(data.packets);
                if (toShow.length > 0) appendRows(toShow);
            }
            // Pass server's total_captured for CAPTURED counter
            // (server may have more than browser received so far)
            updateUI(data.total_captured);
        });
}

// ── RENDER STATS ──────────────────────────────
function renderStats(s) {
    document.getElementById("statTotal").textContent   = s.total;
    document.getElementById("statTCP").textContent     = s.tcp;
    document.getElementById("statUDP").textContent     = s.udp;
    document.getElementById("statICMP").textContent    = s.icmp;
    document.getElementById("statAvgSize").textContent = s.avg_size + " B";
    document.getElementById("statTopSrc").textContent  = s.top_src_ip;
    document.getElementById("statTopDst").textContent  = s.top_dst_ip;
    document.getElementById("statTopSvc").textContent  = s.top_service;

    const b = s.total_bytes;
    const byteStr = b >= 1048576 ? (b/1048576).toFixed(2) + " MB"
                  : b >= 1024    ? (b/1024).toFixed(1)    + " KB"
                  : b + " B";
    document.getElementById("statBytes").textContent = byteStr;
    document.getElementById("hBytes").textContent    = byteStr;

    if (s.total > 0) {
        document.getElementById("barTCP").style.width  = (s.tcp /s.total*100).toFixed(1) + "%";
        document.getElementById("barUDP").style.width  = (s.udp /s.total*100).toFixed(1) + "%";
        document.getElementById("barICMP").style.width = (s.icmp/s.total*100).toFixed(1) + "%";
    }
}

// ── CALC STATS ────────────────────────────────
function calcStats(pList) {
    if (!pList || pList.length === 0) {
        return { total:0, tcp:0, udp:0, icmp:0, avg_size:0,
                 total_bytes:0, top_src_ip:"N/A", top_dst_ip:"N/A", top_service:"N/A" };
    }
    const tcp  = pList.filter(p => p.protocol === "TCP").length;
    const udp  = pList.filter(p => p.protocol === "UDP").length;
    const icmp = pList.filter(p => p.protocol === "ICMP").length;
    const total_bytes = pList.reduce((s, p) => s + p.packet_size, 0);
    const avg_size    = parseFloat((total_bytes / pList.length).toFixed(2));
    const sc = {}, dc = {}, sv = {};
    pList.forEach(p => {
        sc[p.src_ip]  = (sc[p.src_ip]  || 0) + 1;
        dc[p.dst_ip]  = (dc[p.dst_ip]  || 0) + 1;
        sv[p.service] = (sv[p.service] || 0) + 1;
    });
    const top = obj => Object.keys(obj).length
        ? Object.keys(obj).reduce((a, b) => obj[a] > obj[b] ? a : b)
        : "N/A";
    return { total: pList.length, tcp, udp, icmp, avg_size, total_bytes,
             top_src_ip: top(sc), top_dst_ip: top(dc), top_service: top(sv) };
}

// ── FILTER LOCALLY ────────────────────────────
function filterLocally(pList) {
    return pList.filter(p => {
        const protoOk = activeFilters.protocol === "ALL" ||
                        p.protocol === activeFilters.protocol;
        const srcOk   = activeFilters.src_ip === "" ||
                        p.src_ip.includes(activeFilters.src_ip);
        const dstOk   = activeFilters.dst_ip === "" ||
                        p.dst_ip.includes(activeFilters.dst_ip);
        return protoOk && srcOk && dstOk;
    });
}

// ── APPLY FILTER ──────────────────────────────
function applyFilter() {
    activeFilters.protocol = document.getElementById("filterProtocol").value;
    activeFilters.src_ip   = document.getElementById("filterSrcIP").value.trim();
    activeFilters.dst_ip   = document.getElementById("filterDstIP").value.trim();
    const filtered = filterLocally(allPackets);
    clearTable();
    if (filtered.length > 0) appendRows(filtered.slice(-MAX_ROWS));
    updateUI();
}

// ── RESET FILTER ──────────────────────────────
function resetFilter() {
    document.getElementById("filterProtocol").value = "ALL";
    document.getElementById("filterSrcIP").value    = "";
    document.getElementById("filterDstIP").value    = "";
    activeFilters = { protocol: "ALL", src_ip: "", dst_ip: "" };
    clearTable();
    if (allPackets.length > 0) appendRows(allPackets.slice(-MAX_ROWS));
    updateUI();
}

// ── APPEND ROWS ───────────────────────────────
function appendRows(newPackets) {
    const tbody = document.getElementById("packetTableBody");
    const empty = tbody.querySelector(".empty-row");
    if (empty) empty.remove();

    const ordered = [...newPackets].sort((a, b) => a.id - b.id).reverse();
    let html = "";
    ordered.forEach(p => {
        const proto      = esc((p.protocol || "").toUpperCase());
        const rowClass   = proto==="TCP" ? "row-tcp" : proto==="UDP" ? "row-udp" : "row-icmp";
        const badgeClass = proto==="TCP" ? "badge-tcp": proto==="UDP" ? "badge-udp": "badge-icmp";
        const srcPort    = p.src_port === 0 ? "—" : esc(p.src_port);
        const dstPort    = p.dst_port === 0 ? "—" : esc(p.dst_port);
        const size       = p.packet_size >= 1024
                         ? (p.packet_size/1024).toFixed(1) + " KB"
                         : esc(p.packet_size) + " B";
        html += `<tr class="${rowClass}">
            <td>${esc(p.id)}</td><td>${esc(p.time)}</td>
            <td>${esc(p.src_ip)}</td><td>${esc(p.dst_ip)}</td>
            <td><span class="badge ${badgeClass}">${proto}</span></td>
            <td>${srcPort}</td><td>${dstPort}</td>
            <td>${esc(p.service)}</td><td>${size}</td>
            <td>${esc(p.flags || "—")}</td>
        </tr>`;
    });
    tbody.insertAdjacentHTML("afterbegin", html);

    const allRows = tbody.querySelectorAll("tr:not(.empty-row)");
    if (allRows.length > MAX_ROWS) {
        for (let i = MAX_ROWS; i < allRows.length; i++) allRows[i].remove();
    }
}

// ── CLEAR TABLE ───────────────────────────────
function clearTable() {
    document.getElementById("packetTableBody").innerHTML = `
      <tr class="empty-row"><td colspan="10">
        <div class="empty-state">
          <div class="empty-icon">[ ]</div>
          <span>Press START to begin monitoring</span>
        </div>
      </td></tr>`;
}

// ── EXPORT CSV ────────────────────────────────
function exportCSV() { window.location.href = "/export"; }

// ── SAVE CAPTURE ──────────────────────────────
function saveCapture() {
    if (allPackets.length === 0) {
        alert("No packets to save yet.");
        return;
    }
    fetch("/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ packets: allPackets })
    })
        .then(r => r.json())
        .then(data => {
            if (data.status === "saved") {
                alert("Saved " + data.count + " packets to " + data.filename);
                refreshSavesList();
            } else {
                alert("Error: " + (data.error || "Could not save"));
            }
        });
}

// ── REFRESH SAVES LIST ────────────────────────
function refreshSavesList() {
    fetch("/saves")
        .then(r => r.json())
        .then(data => {
            const wrap = document.getElementById("savesList");
            if (data.files.length === 0) {
                wrap.innerHTML = '<div class="saves-empty">No saved captures yet.</div>';
                return;
            }
            let html = "";
            data.files.forEach(file => {
                const sizeKB = (file.size / 1024).toFixed(1);
                html += `<div class="save-item" onclick="loadCapture('${esc(file.name)}')">
                    <span class="save-load-btn">LOAD</span>
                    <span class="save-item-name">${esc(file.name)}</span>
                    <span class="save-item-meta">${sizeKB} KB</span>
                </div>`;
            });
            wrap.innerHTML = html;
        });
}

// ── LOAD CAPTURE ──────────────────────────────
function loadCapture(filename) {
    fetch("/load/" + filename)
        .then(r => r.json())
        .then(data => {
            if (!data.packets) {
                alert("Error: " + (data.error || "Could not load"));
                return;
            }
            clearInterval(packetInterval);
            allPackets    = data.packets;
            lastSeenId    = 0;
            activeFilters = { protocol: "ALL", src_ip: "", dst_ip: "" };
            document.getElementById("filterProtocol").value = "ALL";
            document.getElementById("filterSrcIP").value    = "";
            document.getElementById("filterDstIP").value    = "";
            document.getElementById("statusText").textContent = "LOADED";
            document.getElementById("statusDot").classList.remove("active");
            document.getElementById("btnStart").disabled = false;
            document.getElementById("btnStop").disabled  = true;
            clearTable();
            appendRows(data.packets.slice(-MAX_ROWS));
            // updateUI with no argument → uses allPackets.length for both counters
            updateUI();
        });
}

// ── KEYBOARD SHORTCUTS ────────────────────────
document.addEventListener("keydown", e => {
    if (e.ctrlKey && e.key === "Enter" &&
        !document.getElementById("btnStart").disabled) startMonitoring();
    if (e.key === "Escape" &&
        !document.getElementById("btnStop").disabled)  stopMonitoring();
    if (e.ctrlKey && e.key === "e") { e.preventDefault(); exportCSV(); }
});

refreshSavesList();