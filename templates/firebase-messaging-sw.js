importScripts("https://www.gstatic.com/firebasejs/8.2.0/firebase-app.js");
         importScripts("https://www.gstatic.com/firebasejs/8.2.0/firebase-messaging.js");
    // Request permission for notifications

    // Your web app's Firebase configuration
    const firebaseConfig = {
    apiKey: "AIzaSyDEvlL5aeZfZVKcC8-wqzKzFUVxVO21Xzo",
    authDomain: "farae-df5b2.firebaseapp.com",
    databaseURL: "https://farae-df5b2-default-rtdb.firebaseio.com",
    projectId: "farae-df5b2",
    storageBucket: "farae-df5b2.appspot.com",
    messagingSenderId: "835148268492",
    appId: "1:835148268492:web:80ad338c12a76e5c019369",
    measurementId: "G-RZJHM8Y21L"
  };

    firebase.initializeApp(firebaseConfig);
    const messaging=firebase.messaging();

messaging.setBackgroundMessageHandler(function (payload) {

    const title = payload.data.title || "Default Title";
  const message = payload.data.message || "Default Message";

  const notificationTitle = title;
  const notificationOptions = {
    body: message,
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});
