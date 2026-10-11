import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  User as FirebaseUser,
  updateProfile,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  getDocs,
  collection,
  query,
  orderBy,
  limit,
  updateDoc,
  serverTimestamp,
  getDocFromServer,
  increment,
} from 'firebase/firestore';
import config from '../../firebase-applet-config.json';

// Initialize Firebase App
const app = getApps().length === 0 ? initializeApp(config) : getApp();

// Use named firestore database if configured
export const db = config.firestoreDatabaseId
  ? getFirestore(app, config.firestoreDatabaseId)
  : getFirestore(app);

export const auth = getAuth(app);

// List of designated super-admin emails
export const ADMIN_EMAILS = [
  'shoibaminshadhin@gmail.com',
  'admin@phishguard.ai',
  'admin@gmail.com',
];

export function isAuthorizedAdminEmail(email?: string | null): boolean {
  if (!email) return false;
  return ADMIN_EMAILS.map(e => e.toLowerCase()).includes(email.trim().toLowerCase());
}

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  role: 'admin' | 'user';
  totalScans: number;
  createdAt: string;
  lastLoginAt: string;
  status: 'active' | 'suspended';
}

// Connectivity test probe as specified in Firebase guidelines
export async function testFirestoreConnection(): Promise<boolean> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
    return true;
  } catch (error: any) {
    if (error?.message?.includes('the client is offline')) {
      console.warn('Firestore is in offline mode or database is initializing.');
    }
    return false;
  }
}

// Register a new user
export async function registerWithEmail(
  email: string,
  pass: string,
  name: string
): Promise<UserProfile> {
  const cred = await createUserWithEmailAndPassword(auth, email, pass);
  const user = cred.user;

  if (name && auth.currentUser) {
    try {
      await updateProfile(auth.currentUser, { displayName: name });
    } catch {}
  }

  const role = isAuthorizedAdminEmail(email) ? 'admin' : 'user';
  const profile: UserProfile = {
    uid: user.uid,
    email: user.email || email,
    displayName: name || email.split('@')[0],
    role,
    totalScans: 0,
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString(),
    status: 'active',
  };

  await setDoc(doc(db, 'users', user.uid), profile);
  return profile;
}

// Sign in existing user
export async function loginWithEmail(email: string, pass: string): Promise<UserProfile> {
  const cred = await signInWithEmailAndPassword(auth, email, pass);
  const user = cred.user;

  // Fetch or sync user document
  const userRef = doc(db, 'users', user.uid);
  const snap = await getDoc(userRef);

  let profile: UserProfile;
  if (snap.exists()) {
    profile = snap.data() as UserProfile;
    // Update last login timestamp and enforce admin role if designated admin email
    const isSpecialAdmin = isAuthorizedAdminEmail(user.email);
    const updatedRole = isSpecialAdmin ? 'admin' : profile.role;
    
    await updateDoc(userRef, {
      lastLoginAt: new Date().toISOString(),
      role: updatedRole,
    });
    profile.lastLoginAt = new Date().toISOString();
    profile.role = updatedRole;
  } else {
    // Document doesn't exist yet, bootstrap it
    const role = isAuthorizedAdminEmail(user.email) ? 'admin' : 'user';
    profile = {
      uid: user.uid,
      email: user.email || email,
      displayName: user.displayName || email.split('@')[0],
      role,
      totalScans: 0,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      status: 'active',
    };
    await setDoc(userRef, profile);
  }

  return profile;
}

// Sign out user
export async function logoutUser(): Promise<void> {
  await signOut(auth);
}

// Fetch single user profile
export async function fetchUserProfile(uid: string): Promise<UserProfile | null> {
  try {
    const snap = await getDoc(doc(db, 'users', uid));
    if (snap.exists()) {
      return snap.data() as UserProfile;
    }
  } catch (err) {
    console.error('Error fetching user profile:', err);
  }
  return null;
}

// Record scan in Firestore
export async function recordScanInDb(
  scanData: {
    userId: string;
    userEmail: string;
    url: string;
    defangedUrl: string;
    verdict: string;
    probability: number;
    riskLevel: string;
  }
): Promise<void> {
  try {
    const scanId = 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
    await setDoc(doc(db, 'scans', scanId), {
      ...scanData,
      timestamp: new Date().toISOString(),
    });

    // If registered user, increment their totalScans counter
    if (scanData.userId && scanData.userId !== 'guest') {
      const userRef = doc(db, 'users', scanData.userId);
      await updateDoc(userRef, {
        totalScans: increment(1),
      });
    }
  } catch (err) {
    console.warn('Could not record scan in cloud db (guest or offline):', err);
  }
}

// Admin: Fetch all users
export async function adminFetchAllUsers(): Promise<UserProfile[]> {
  const querySnap = await getDocs(collection(db, 'users'));
  const users: UserProfile[] = [];
  querySnap.forEach((doc) => {
    users.push(doc.data() as UserProfile);
  });
  return users.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
}

// Admin: Fetch recent scans
export async function adminFetchRecentScans(maxCount = 50): Promise<any[]> {
  try {
    const q = query(collection(db, 'scans'), orderBy('timestamp', 'desc'), limit(maxCount));
    const querySnap = await getDocs(q);
    const scans: any[] = [];
    querySnap.forEach((doc) => {
      scans.push({ id: doc.id, ...doc.data() });
    });
    return scans;
  } catch {
    // Fallback without orderBy if index is still generating
    const querySnap = await getDocs(collection(db, 'scans'));
    const scans: any[] = [];
    querySnap.forEach((doc) => {
      scans.push({ id: doc.id, ...doc.data() });
    });
    return scans.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, maxCount);
  }
}

// Admin: Toggle user status
export async function adminUpdateUserStatus(uid: string, status: 'active' | 'suspended'): Promise<void> {
  await updateDoc(doc(db, 'users', uid), { status });
}

// Admin: Toggle user role
export async function adminUpdateUserRole(uid: string, role: 'admin' | 'user'): Promise<void> {
  await updateDoc(doc(db, 'users', uid), { role });
}
