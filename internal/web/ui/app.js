/* Same-origin progressive enhancement only. No tokens, HTML or profile history in browser storage. */
(() => {
  const message = document.getElementById('network-message');
  const refreshNavigation = () => {
    const panel = document.getElementById('portal-panel');
    if (!panel) return;
    document.querySelectorAll('.portal-nav a[data-view]').forEach(link => {
      if (link.dataset.view === panel.dataset.view) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    const current = document.getElementById('current-page');
    if (current) current.textContent = panel.dataset.title || 'Participant portal';
    document.title = `${panel.dataset.title || 'Participant portal'} · OSEE`;
  };
  document.addEventListener('htmx:afterSwap', event => {
    if (message) message.hidden = true;
    refreshNavigation();
    const heading = document.querySelector('#portal-panel h1');
    if (heading) heading.focus({preventScroll: true});
  });
  document.addEventListener('htmx:historyRestore', refreshNavigation);
  ['htmx:sendError', 'htmx:responseError', 'htmx:timeout'].forEach(type => {
    document.addEventListener(type, event => {
      if (event.detail?.xhr?.getResponseHeader('HX-Redirect')) return;
      if (message) message.hidden = false;
    });
  });
  refreshNavigation();
})();
