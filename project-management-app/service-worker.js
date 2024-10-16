let deferredPrompt;
const addToHomeBtn = document.getElementById('addToHomeBtn');

window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault(); // Prevent the mini-info bar from appearing
    deferredPrompt = e; // Stash the event so it can be triggered later
    addToHomeBtn.style.display = 'block'; // Show the button
});

addToHomeBtn.addEventListener('click', async () => {
    addToHomeBtn.style.display = 'none'; // Hide the button after clicking
    if (deferredPrompt) {
        deferredPrompt.prompt(); // Show the install prompt
        const { outcome } = await deferredPrompt.userChoice; // Wait for the user's response
        if (outcome === 'accepted') {
            console.log('User accepted the A2HS prompt');
        } else {
            console.log('User dismissed the A2HS prompt');
        }
        deferredPrompt = null; // Clear the prompt
    }
});

// Hide the button if the app is already installed
window.addEventListener('appinstalled', () => {
    addToHomeBtn.style.display = 'none';
});
