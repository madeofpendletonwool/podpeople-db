// PodPeopleDB: progressive enhancement. Every page works without this; this makes it quick.
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") node.className = attrs[k];
      else if (k === "text") node.textContent = attrs[k];
      else if (k === "html") node.innerHTML = attrs[k];
      else if (attrs[k] !== null && attrs[k] !== undefined) node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return node;
  }

  function icon(name) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    var use = document.createElementNS(ns, "use");
    use.setAttribute("href", "#i-" + name);
    svg.appendChild(use);
    return svg;
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(self, args); }, ms);
    };
  }

  function api(path, opts) {
    opts = opts || {};
    var init = { method: opts.method || "GET", headers: { Accept: "application/json" } };
    if (opts.body) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error((data && data.error) || (r.status === 429 ? "Too many additions, slow down a little." : "Something went wrong."));
        return data;
      });
    });
  }

  // ---------- Toasts ----------
  function toast(message, kind) {
    var box = $("[data-toasts]");
    if (!box) return;
    var t = el("div", { class: "toast " + (kind || "ok"), role: "status" }, [icon(kind === "err" ? "warn" : "check"), el("span", { class: "grow", text: message })]);
    box.appendChild(t);
    setTimeout(function () {
      t.classList.add("leaving");
      setTimeout(function () { t.remove(); }, 250);
    }, kind === "err" ? 6000 : 3500);
  }

  // ---------- Avatars ----------
  function initials(name) {
    var words = (name || "").trim().split(/\s+/).filter(function (w) { return /[\p{L}\p{N}]/u.test(w.charAt(0)); });
    if (!words.length) return "?";
    var s = words[0].charAt(0);
    if (words.length > 1) s += words[words.length - 1].charAt(0);
    return s.toUpperCase();
  }
  function avatarColor(name) {
    // Same hash as the server (djb2-xor over UTF-8 bytes).
    var bytes = new TextEncoder().encode(name);
    var h = 5381;
    for (var i = 0; i < bytes.length; i++) h = (Math.imul(h, 33) ^ bytes[i]) >>> 0;
    return "hsl(" + (h % 360) + " 38% 42%)";
  }
  function imgUrl(u) { return u ? "/img?u=" + encodeURIComponent(u) : null; }
  function avatar(person, size) {
    var cls = "avatar " + (size || "");
    if (person.img) {
      var img = el("img", { class: cls, src: imgUrl(person.img), alt: "", loading: "lazy", "data-fallback": initials(person.name) });
      img.style.setProperty("--avatar-bg", avatarColor(person.name));
      return img;
    }
    var span = el("span", { class: cls + " initials", "aria-hidden": "true", text: initials(person.name) });
    span.style.setProperty("--avatar-bg", avatarColor(person.name));
    return span;
  }
  document.addEventListener("error", function (e) {
    var img = e.target;
    if (img.tagName !== "IMG" || !img.classList.contains("avatar") || !img.dataset.fallback) return;
    var span = el("span", { class: img.className + " initials", "aria-hidden": "true", text: img.dataset.fallback });
    span.style.cssText = img.style.cssText;
    img.replaceWith(span);
  }, true);
  function personUrl(p) { return "/people/" + p.id + "/" + p.slug; }

  // ---------- Theme + menu ----------
  $$("[data-theme-toggle]").forEach(function (b) {
    b.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
      var next = current === "light" ? "dark" : "light";
      root.dataset.theme = next;
      try { localStorage.setItem("pp-theme", next); } catch (e) {}
    });
  });
  $$("[data-menu-toggle]").forEach(function (b) {
    b.addEventListener("click", function () { var m = $("[data-menu]"); if (m) m.classList.toggle("open"); });
  });

  // ---------- Expandable descriptions ----------
  $$("[data-expandable]").forEach(function (p) {
    if (p.scrollHeight <= p.clientHeight + 2) return;
    p.style.cursor = "pointer";
    p.title = "Show more";
    p.addEventListener("click", function () { p.classList.toggle("clamp-3"); });
  });

  // ---------- Confirm ----------
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  // ---------- Keyboard-navigable suggestion lists ----------
  function suggestList(box, onPick) {
    var items = [], active = -1;
    function setActive(i) {
      items.forEach(function (it, j) { it.classList.toggle("active", j === i); });
      active = i;
      if (items[i]) items[i].scrollIntoView({ block: "nearest" });
    }
    return {
      render: function (nodes) {
        box.innerHTML = "";
        nodes.forEach(function (n) { box.appendChild(n); });
        items = $$(".suggest-item", box);
        items.forEach(function (it, i) {
          it.addEventListener("mousedown", function (e) { e.preventDefault(); onPick(it, e); });
          it.addEventListener("mousemove", function () { if (active !== i) setActive(i); });
        });
        active = -1;
        box.hidden = nodes.length === 0;
      },
      hide: function () { box.hidden = true; active = -1; },
      key: function (e) {
        if (box.hidden || !items.length) return false;
        if (e.key === "ArrowDown") { setActive((active + 1) % items.length); e.preventDefault(); return true; }
        if (e.key === "ArrowUp") { setActive((active - 1 + items.length) % items.length); e.preventDefault(); return true; }
        if (e.key === "Escape") { box.hidden = true; return true; }
        if (e.key === "Enter" && active >= 0) { e.preventDefault(); onPick(items[active], e); return true; }
        return false;
      },
    };
  }

  // ---------- Site search typeahead ----------
  $$("[data-typeahead]").forEach(function (wrap) {
    var input = $("input", wrap);
    var box = el("div", { class: "suggest", hidden: "" });
    wrap.appendChild(box);
    var list = suggestList(box, function (item) { window.location.href = item.getAttribute("href"); });
    var seq = 0;
    var run = debounce(function () {
      var q = input.value.trim();
      if (q.length < 2) { list.hide(); return; }
      var mine = ++seq;
      api("/api/v2/people/search?limit=6&q=" + encodeURIComponent(q)).then(function (people) {
        if (mine !== seq) return;
        var nodes = [];
        if (people.length) nodes.push(el("div", { class: "suggest-label", text: "People" }));
        people.forEach(function (p) {
          nodes.push(el("a", { class: "suggest-item", href: personUrl(p) }, [
            avatar(p, "sm"),
            el("span", { class: "truncate" }, [el("div", { text: p.name }), el("div", { class: "meta truncate", text: p.known_for || "" })]),
          ]));
        });
        nodes.push(el("a", { class: "suggest-item", href: "/search?q=" + encodeURIComponent(q) }, [
          icon("search"), el("span", { text: "Search podcasts and people for “" + q + "”" }),
        ]));
        list.render(nodes);
      }).catch(function () { list.hide(); });
    }, 140);
    input.addEventListener("input", run);
    input.addEventListener("keydown", function (e) { list.key(e); });
    input.addEventListener("blur", function () { setTimeout(list.hide, 120); });
    input.addEventListener("focus", function () { if (input.value.trim().length >= 2) run(); });
  });

  // ---------- Names ----------
  // Same rules as the server's split_names: commas, semicolons, new lines, "and", "&", "+", "with".
  function splitNames(text) {
    var out = [], seen = {};
    text.split(/[\n,;]/).forEach(function (line) {
      var parts = [[]];
      line.trim().split(/\s+/).forEach(function (w) {
        if (!w) return;
        if (/^(and|&|\+|with)$/i.test(w)) parts.push([]);
        else parts[parts.length - 1].push(w);
      });
      parts.forEach(function (p) {
        var n = p.join(" ").trim();
        var key = n.toLowerCase();
        if (n && !seen[key]) { seen[key] = 1; out.push(n); }
      });
    });
    return out;
  }

  // ---------- People tiles ----------
  function personTile(credit, role) {
    var p = credit.person;
    var tile = el("a", { class: "person-tile just-added", href: personUrl(p) }, [
      avatar(p, "lg"),
      el("span", { class: "name", text: p.name }),
      el("span", { class: "badges" }, [
        el("span", { class: "badge role", text: role || credit.role }),
        p.verified && !credit.new_person ? null : el("span", { class: "badge unverified", text: "unverified" }),
      ]),
    ]);
    return tile;
  }
  function miniPerson(credit) {
    var p = credit.person;
    return el("a", { class: "mini-person", href: personUrl(p) }, [avatar(p, "xs"), p.name + " ", el("span", { class: "role", text: credit.role })]);
  }

  function showAdded(root, result) {
    var grid = $("[data-people-grid]");
    var empty = $("[data-people-empty]");
    var added = result.credits.filter(function (c) { return c.created; });
    if (grid) {
      added.slice().reverse().forEach(function (c) {
        // Don't duplicate a tile already on the page.
        var exists = $$("a.person-tile", grid).some(function (a) { return a.getAttribute("href") === personUrl(c.person); });
        if (!exists) grid.insertBefore(personTile(c), grid.firstChild);
      });
      if (added.length) { grid.hidden = false; if (empty) empty.remove(); }
      var count = $("[data-people-count]");
      if (count) count.textContent = $$("a.person-tile", grid).length;
    }
    var names = added.map(function (c) { return c.person.name; });
    if (names.length) toast("Added " + listNames(names) + ". Thanks!");
    else toast("They were already listed. Thanks anyway!");
  }
  function listNames(n) {
    if (n.length <= 1) return n.join("");
    return n.slice(0, -1).join(", ") + " and " + n[n.length - 1];
  }

  // ---------- Person picker (chips + typeahead of existing people) ----------
  function personPicker(chipsRoot) {
    var input = $("[data-name-input]", chipsRoot);
    var box = $("[data-person-suggest]", chipsRoot);
    var chips = []; // {name} or {person_id, name}

    function draw() {
      $$(".chip", chipsRoot).forEach(function (c) { c.remove(); });
      chips.forEach(function (c, i) {
        var x = el("button", { class: "x", type: "button", "aria-label": "Remove " + c.name }, [icon("x")]);
        x.addEventListener("click", function () { chips.splice(i, 1); draw(); input.focus(); });
        var chip = el("span", { class: "chip" + (c.person_id ? " existing" : ""), title: c.person_id ? "Existing person" : "New person" }, [el("span", { class: "truncate", text: c.name }), x]);
        chipsRoot.insertBefore(chip, input);
      });
      input.placeholder = chips.length ? "Add another" : "Add a name";
    }
    function addNames(text) {
      splitNames(text).forEach(function (n) {
        if (!chips.some(function (c) { return c.name.toLowerCase() === n.toLowerCase(); })) chips.push({ name: n });
      });
      draw();
    }
    function addExisting(p) {
      if (!chips.some(function (c) { return c.person_id === p.id; })) chips.push({ person_id: p.id, name: p.name });
      draw();
    }

    var list = suggestList(box, function (item) {
      if (item.dataset.personId) addExisting({ id: Number(item.dataset.personId), name: item.dataset.name });
      else addNames(item.dataset.name);
      input.value = "";
      list.hide();
      input.focus();
    });
    var seq = 0;
    var search = debounce(function () {
      var q = input.value.trim();
      if (q.length < 2 || /[,;\n]/.test(q)) { list.hide(); return; }
      var mine = ++seq;
      api("/api/v2/people/search?limit=5&q=" + encodeURIComponent(q)).then(function (people) {
        if (mine !== seq) return;
        var nodes = people.map(function (p) {
          return el("div", { class: "suggest-item", "data-person-id": p.id, "data-name": p.name }, [
            avatar(p, "sm"),
            el("span", { class: "truncate" }, [el("div", { text: p.name }), el("div", { class: "meta truncate", text: p.known_for || "No shows yet" })]),
          ]);
        });
        var exact = people.some(function (p) { return p.name.toLowerCase() === q.toLowerCase(); });
        if (!exact) {
          nodes.push(el("div", { class: "suggest-item", "data-name": q }, [
            el("span", { class: "avatar sm initials", text: "+" }),
            el("span", {}, [el("div", { text: "Add “" + q + "”" }), el("div", { class: "meta", text: "New person" })]),
          ]));
        }
        list.render(nodes);
      }).catch(function () { list.hide(); });
    }, 140);

    input.addEventListener("input", function () {
      if (/[,;\n]/.test(input.value) && splitNames(input.value).length > 1) {
        var last = input.value.match(/[^,;\n]*$/)[0];
        addNames(input.value.slice(0, input.value.length - last.length));
        input.value = last.trimStart();
      }
      search();
    });
    input.addEventListener("paste", function (e) {
      var text = (e.clipboardData || window.clipboardData).getData("text");
      if (splitNames(text).length > 1) { e.preventDefault(); addNames(text); list.hide(); }
    });
    input.addEventListener("keydown", function (e) {
      if (list.key(e)) return;
      if (e.key === "Enter" && input.value.trim()) { e.preventDefault(); addNames(input.value); input.value = ""; list.hide(); }
      else if (e.key === "Backspace" && !input.value && chips.length) { chips.pop(); draw(); }
    });
    input.addEventListener("blur", function () { setTimeout(list.hide, 120); });
    chipsRoot.addEventListener("click", function (e) { if (e.target === chipsRoot) input.focus(); });

    return {
      take: function () {
        if (input.value.trim()) { addNames(input.value); input.value = ""; }
        return chips.slice();
      },
      clear: function () { chips = []; draw(); },
      focus: function () { input.focus(); },
    };
  }

  function submitPeople(payload, button) {
    if (button) { button.classList.add("is-busy"); button.disabled = true; }
    return api("/api/v2/submissions", { method: "POST", body: payload }).finally(function () {
      if (button) { button.classList.remove("is-busy"); button.disabled = false; }
    });
  }

  // ---------- Contribute widget ----------
  $$("[data-contribute]").forEach(function (root) {
    var form = $("[data-contribute-form]", root);
    if (!form) return;
    var picker = personPicker($("[data-chips]", root));
    var podcastId = Number(root.dataset.podcastId);
    var episodeId = root.dataset.episodeId ? Number(root.dataset.episodeId) : null;
    var submit = $("[data-submit]", form);

    function send(entries, role) {
      if (!entries.length) { toast("Type a name first.", "err"); picker.focus(); return; }
      var img = form.img ? form.img.value.trim() : "";
      var website = form.website ? form.website.value.trim() : "";
      var people = entries.map(function (c) {
        var p = c.person_id ? { person_id: c.person_id } : { name: c.name };
        p.role = role;
        if (entries.length === 1) { if (img) p.img = img; if (website) p.website = website; }
        return p;
      });
      var body = { podcast: { id: podcastId }, people: people, homepage: form.homepage ? form.homepage.value : "" };
      if (episodeId) body.episode = { id: episodeId };
      return submitPeople(body, submit).then(function (result) {
        picker.clear();
        if (form.img) form.img.value = "";
        if (form.website) form.website.value = "";
        showAdded(root, result);
        picker.focus();
      }).catch(function (err) { toast(err.message, "err"); });
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      send(picker.take(), form.role.value);
    });

    $$("[data-suggest-name]", root).forEach(function (b) {
      b.addEventListener("click", function () {
        var name = b.dataset.suggestName;
        submitPeople({ podcast: { id: podcastId }, people: [{ name: name, role: "host" }] }, b).then(function (result) {
          b.remove();
          var box = $("[data-suggestions]", root);
          if (box && !$("[data-suggest-name]", box)) box.remove();
          showAdded(root, result);
        }).catch(function (err) { toast(err.message, "err"); });
      });
    });
  });

  // ---------- Per-episode "who's on this?" ----------
  $$("[data-add-guest]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var episodeId = Number(btn.dataset.addGuest);
      var line = btn.closest("[data-episode-people]");
      var host = line.parentElement;
      var existing = $(".inline-add", host);
      if (existing) { $("input", existing).focus(); return; }
      var podcastId = Number($("[data-contribute]").dataset.podcastId);
      var chips = el("div", { class: "chip-input", "data-chips": "" }, [
        el("input", { type: "text", "data-name-input": "", placeholder: "Guest names", "aria-label": "Guest names" }),
        el("div", { class: "suggest", hidden: "", "data-person-suggest": "" }),
      ]);
      var add = el("button", { class: "btn btn-primary btn-sm", type: "submit", text: "Add" });
      var cancel = el("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Cancel" });
      var form = el("form", { class: "inline-add", autocomplete: "off" }, [chips, el("div", { class: "contribute-row" }, [add, cancel])]);
      host.appendChild(form);
      var picker = personPicker(chips);
      picker.focus();
      cancel.addEventListener("click", function () { form.remove(); });
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var entries = picker.take();
        if (!entries.length) return;
        var people = entries.map(function (c) { return c.person_id ? { person_id: c.person_id, role: "guest" } : { name: c.name, role: "guest" }; });
        submitPeople({ podcast: { id: podcastId }, episode: { id: episodeId }, people: people }, add).then(function (result) {
          result.credits.filter(function (c) { return c.created; }).forEach(function (c) { line.insertBefore(miniPerson(c), btn); });
          form.remove();
          var names = result.credits.filter(function (c) { return c.created; }).map(function (c) { return c.person.name; });
          toast(names.length ? "Added " + listNames(names) + ". Thanks!" : "Already listed.");
        }).catch(function (err) { toast(err.message, "err"); });
      });
    });
  });

  // ---------- Person edit ----------
  $$("[data-edit-toggle]").forEach(function (b) {
    b.addEventListener("click", function () {
      var f = $("[data-person-edit]");
      if (!f) return;
      f.hidden = !f.hidden;
      if (!f.hidden) f.name.focus();
    });
  });
  $$("[data-person-edit]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var button = $("button.btn-primary", f);
      button.disabled = true;
      api("/api/v2/people/" + f.dataset.personEdit + "/edit", {
        method: "POST",
        body: { name: f.name.value, img: f.img.value, website: f.website.value, bio: f.bio.value, homepage: f.homepage.value },
      }).then(function (r) {
        toast("Saved. Thanks!");
        setTimeout(function () { window.location.href = personUrl(r.person); }, 600);
      }).catch(function (err) { toast(err.message, "err"); button.disabled = false; });
    });
  });

  // ---------- Add a podcast with no feed ----------
  $$("[data-manual-podcast]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      e.preventDefault();
      var names = splitNames(f.people.value);
      if (!names.length) { toast("Add at least one person.", "err"); return; }
      var button = $("button", f);
      submitPeople({
        podcast: { title: f.title.value.trim(), link: f.link.value.trim() || null },
        people: names.map(function (n) { return { name: n }; }),
        homepage: f.homepage.value,
      }, button).then(function (r) {
        if (r.podcast) window.location.href = "/podcasts/" + r.podcast.id;
      }).catch(function (err) { toast(err.message, "err"); });
    });
  });

  // Flash messages from admin redirects become toasts, and leave the URL clean.
  var params = new URLSearchParams(location.search);
  if (params.get("flash")) {
    toast(params.get("flash"));
    params.delete("flash");
    var q = params.toString();
    history.replaceState(null, "", location.pathname + (q ? "?" + q : "") + location.hash);
  }
})();
