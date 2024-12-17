document.addEventListener('DOMContentLoaded', function() {
    const addSiteForm = document.getElementById('addSiteForm');
    const protectedSites = document.getElementById('protectedSites');
    const wafLog = document.getElementById('wafLog');

    // Handle form submission
    addSiteForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const siteName = document.getElementById('siteName').value;
        const targetUrl = document.getElementById('targetUrl').value;

        try {
            const response = await fetch('/api/sites', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: siteName,
                    url: targetUrl
                })
            });

            if (response.ok) {
                addSiteForm.reset();
                loadProtectedSites();
            } else {
                alert('Failed to add site');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error adding site');
        }
    });

    // Load protected sites
    async function loadProtectedSites() {
        try {
            const response = await fetch('/api/sites');
            const sites = await response.json();
            
            protectedSites.innerHTML = sites.map(site => `
                <div class="site-card">
                    <span class="status ${site.active ? 'active' : 'inactive'}"></span>
                    <strong>${site.name}</strong>
                    <div class="text-muted">${site.url}</div>
                    <button class="btn btn-sm btn-danger float-end" onclick="deleteSite('${site.id}')">Remove</button>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error:', error);
        }
    }

    // Delete a protected site
    window.deleteSite = async function(siteId) {
        if (!confirm('Are you sure you want to remove this site?')) {
            return;
        }

        try {
            const response = await fetch(`/api/sites/${siteId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                loadProtectedSites();
            } else {
                alert('Failed to delete site');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error deleting site');
        }
    }

    // WebSocket connection for real-time logs
    const ws = new WebSocket(`ws://${window.location.host}/ws/logs`);
    
    ws.onmessage = function(event) {
        const log = JSON.parse(event.data);
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${log.level}`;
        logEntry.textContent = `[${new Date().toISOString()}] ${log.message}`;
        wafLog.appendChild(logEntry);
        wafLog.scrollTop = wafLog.scrollHeight;
    };

    // Initial load of protected sites
    loadProtectedSites();
});
