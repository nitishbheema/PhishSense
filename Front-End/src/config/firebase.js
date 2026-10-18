import { initializeApp, getApps } from 'firebase/app'
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth'

// Read Firebase web configuration from Vite environment variables
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || '',
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || '',
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || '',
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || '',
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
  appId: import.meta.env.VITE_FIREBASE_APP_ID || '',
}

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey &&
  firebaseConfig.authDomain &&
  firebaseConfig.projectId
)

let app = null
let auth = null
let googleProvider = null

if (isFirebaseConfigured) {
  try {
    app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0]
    auth = getAuth(app)
    googleProvider = new GoogleAuthProvider()
    googleProvider.setCustomParameters({ prompt: 'select_account' })
  } catch (err) {
    console.warn('[Firebase] Initialization error:', err)
  }
}

/**
 * Triggers native Google Sign-In popup if Firebase is configured.
 * Returns { email, name, picture, idToken } or throws error.
 */
export async function signInWithGoogleFirebase() {
  if (!isFirebaseConfigured || !auth || !googleProvider) {
    throw new Error('FIREBASE_NOT_CONFIGURED')
  }

  const result = await signInWithPopup(auth, googleProvider)
  const user = result.user
  return {
    email: user.email,
    name: user.displayName || user.email.split('@')[0],
    picture: user.photoURL || `https://api.dicebear.com/7.x/identicon/svg?seed=${encodeURIComponent(user.email)}`,
    uid: user.uid,
  }
}
