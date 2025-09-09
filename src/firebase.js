// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getFirestore } from 'firebase/firestore';
import { getAuth } from 'firebase/auth';
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDekNsRveuvBEzWqlKJSfmFYPMqirJUBkM",
  authDomain: "cimb-monitoring-system.firebaseapp.com",
  projectId: "cimb-monitoring-system",
  storageBucket: "cimb-monitoring-system.firebasestorage.app",
  messagingSenderId: "914344151299",
  appId: "1:914344151299:web:61e3a201dc2cdde25ec136",
  measurementId: "G-Q2Q8VVQD37"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
export const auth = getAuth(app);