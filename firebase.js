// firebase.js - ONE CONFIG FOR ALL PAGES
const firebaseConfig = {
  apiKey: "AIzaSyA98aUPfUh0OTf1PHOb7KoG34YrUJH8qUQ",
  authDomain: "fednice-rental-system.firebaseapp.com",
  projectId: "fednice-rental-system",
  storageBucket: "fednice-rental-system.firebasestorage.app",
  messagingSenderId: "870466178034",
  appId: "1:870466178034:web:6941c2c8fb3314d37cb96b",
  measurementId: "G-HEF54P2J7S"
};
firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();
