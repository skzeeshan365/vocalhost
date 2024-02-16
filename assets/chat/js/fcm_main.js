const firebaseConfig = {
        apiKey: _356,
        authDomain: "farae-df5b2.firebaseapp.com",
        databaseURL: "https://farae-df5b2-default-rtdb.firebaseio.com",
        projectId: "farae-df5b2",
        storageBucket: "farae-df5b2.appspot.com",
        messagingSenderId: "835148268492",
        appId: "1:835148268492:web:80ad338c12a76e5c019369",
        measurementId: "G-RZJHM8Y21L"
    };
    // Initialize Firebase
    firebase.initializeApp(firebaseConfig);
    firebase.analytics();
    const messaging = firebase.messaging();

    // Check if permission is already granted
    if (Notification.permission === 'granted') {
        messaging.onMessage((payload) => {

        });
    } else {
        // Request notification permission
        messaging.requestPermission()
            .then(() => {
                console.log("Notification permission granted.");
                handlePermission();
            })
            .catch((err) => {
                console.log("Unable to get permission to notify.", err);
            });
    }

    function handlePermission() {
        // Get the FCM token
        messaging.getToken()
            .then((token) => {
                // Send the token to your Django server
                sendRegistrationTokenToServer(token);
            })
            .catch((error) => {
                console.error('Error getting FCM token:', error);
            });
    }

    function sendRegistrationTokenToServer(token) {
        // Use AJAX, fetch, or any other method to send the token to your Django server
        fetch('/push/register_device/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({token}),
        })
            .then((response) => response.json())
            .then((data) => console.log('Server response:', data))
            .catch((error) => console.error('Error:', error));
    }

    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/firebase-messaging-sw.js')
            .then((registration) => {
            })
            .catch((error) => {
                console.error('Service Worker registration failed:', error);
            });
    }