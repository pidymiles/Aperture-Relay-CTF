const list = document.querySelector("#incident-list");
const detail = document.querySelector("#incident-detail");
const counter = document.querySelector("#incident-count");

function badgeClass(value) {
  return `badge badge-${String(value).toLowerCase().replaceAll(" ", "-")}`;
}

async function loadIncidents() {
  try {
    const response = await fetch("/api/incidents", { credentials: "same-origin" });
    if (!response.ok) throw new Error(response.status);
    const data = await response.json();
    counter.textContent = data.count;
    list.replaceChildren();
    for (const incident of data.incidents) {
      const button = document.createElement("button");
      button.className = "incident-row";
      button.dataset.objectToken = incident.object_token;

      const copy = document.createElement("span");
      copy.className = "incident-copy";
      const title = document.createElement("strong");
      title.textContent = incident.title;
      const meta = document.createElement("small");
      meta.textContent = `${incident.reference} // ${incident.severity} // ${incident.opened_at}`;
      copy.append(title, meta);

      const state = document.createElement("span");
      state.className = badgeClass(incident.status);
      state.textContent = incident.status;
      button.append(copy, state);
      button.addEventListener("click", () => loadIncident(incident.object_token, button));
      list.append(button);
    }
  } catch (error) {
    list.innerHTML = '<div class="alert">Relay synchronization failed.</div>';
  }
}

async function loadIncident(objectToken, selected) {
  document.querySelectorAll(".incident-row").forEach((row) => row.classList.remove("selected"));
  selected?.classList.add("selected");
  detail.innerHTML = '<div class="loading">Resolving object reference…</div>';
  try {
    const response = await fetch(`/api/incidents/${objectToken}`, { credentials: "same-origin" });
    if (!response.ok) throw new Error(response.status);
    const { incident } = await response.json();
    detail.replaceChildren();

    const head = document.createElement("div");
    head.className = "detail-head";
    const ref = document.createElement("span");
    ref.className = "kicker";
    ref.textContent = incident.reference;
    const title = document.createElement("h2");
    title.textContent = incident.title;
    const state = document.createElement("span");
    state.className = badgeClass(incident.status);
    state.textContent = incident.status;
    head.append(ref, title, state);

    const facts = document.createElement("dl");
    facts.className = "facts";
    for (const [label, value] of [["Owner", incident.owner], ["Severity", incident.severity], ["Opened", incident.opened_at]]) {
      const item = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = label;
      dd.textContent = value;
      item.append(dt, dd);
      facts.append(item);
    }

    detail.append(head, facts, textSection("Summary", incident.summary), textSection("Restricted notes", incident.restricted_notes, "restricted"));
    if (incident.attachment_url) {
      const section = document.createElement("section");
      section.className = "record-section attachment";
      const heading = document.createElement("h3");
      heading.textContent = "Evidence attachment";
      const link = document.createElement("a");
      link.href = incident.attachment_url;
      link.download = incident.attachment;
      link.textContent = `Download ${incident.attachment}`;
      section.append(heading, link);
      detail.append(section);
    }
  } catch (error) {
    detail.innerHTML = '<div class="alert">Object reference could not be resolved.</div>';
  }
}

function textSection(title, value, extraClass = "") {
  const section = document.createElement("section");
  section.className = `record-section ${extraClass}`.trim();
  const heading = document.createElement("h3");
  heading.textContent = title;
  const body = document.createElement("p");
  body.textContent = value;
  section.append(heading, body);
  return section;
}

loadIncidents();
