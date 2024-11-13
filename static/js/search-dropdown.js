document.addEventListener('DOMContentLoaded', function() {
    let currentHighlightedIndex = -1;

    document.querySelector('input[name="name"]').addEventListener('keydown', function(e) {
        const suggestions = document.querySelectorAll('.suggestion-item');
        
        if (!suggestions.length) return;

        switch(e.key) {
            case 'ArrowDown':
                e.preventDefault();
                currentHighlightedIndex = Math.min(currentHighlightedIndex + 1, suggestions.length - 1);
                updateHighlight(suggestions);
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                currentHighlightedIndex = Math.max(currentHighlightedIndex - 1, 0);
                updateHighlight(suggestions);
                break;
                
            case 'Enter':
                e.preventDefault();
                if (currentHighlightedIndex >= 0) {
                    suggestions[currentHighlightedIndex].click();
                }
                break;
                
            case 'Escape':
                closeSuggestions();
                break;
        }
    });

    function updateHighlight(suggestions) {
        suggestions.forEach((item, index) => {
            if (index === currentHighlightedIndex) {
                item.classList.add('highlighted');
                item.scrollIntoView({ block: 'nearest' });
            } else {
                item.classList.remove('highlighted');
            }
        });
    }

    // Handle HTMX after request for search results
    document.body.addEventListener('htmx:afterRequest', function(evt) {
        if (evt.detail.target.id === 'search-results') {
            if (evt.detail.target.innerHTML.trim()) {
                evt.detail.target.classList.remove('hidden');
            } else {
                evt.detail.target.classList.add('hidden');
            }
            currentHighlightedIndex = -1;
        }
    });

    // Handle form updates after selecting a host
    document.body.addEventListener('htmx:afterRequest', function(evt) {
        if (evt.detail.target.id === 'host-form' && evt.detail.xhr.status === 200) {
            try {
                const host = JSON.parse(evt.detail.xhr.response);
                document.querySelector('input[name="name"]').value = host.name;
                document.querySelector('select[name="role"]').value = host.role;
                document.querySelector('textarea[name="description"]').value = host.description;
                document.querySelector('input[name="link"]').value = host.link;
                document.querySelector('input[name="img"]').value = host.img || '';
                closeSuggestions();
            } catch (e) {
                console.error('Error parsing host details:', e);
            }
        }
    });

    function closeSuggestions() {
        const searchResults = document.querySelector('#search-results');
        searchResults.classList.add('hidden');
        currentHighlightedIndex = -1;
    }

    // Close suggestions when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('input[name="name"]') && !e.target.closest('#search-results')) {
            closeSuggestions();
        }
    });
});