import React, { createContext, useContext, useState, useEffect } from 'react';
import {
  onAuthStateChanged,
  User as FirebaseUser,
} from 'firebase/auth';
import {
  auth,
  UserProfile,
  fetchUserProfile,
  loginWithEmail,
  registerWithEmail,
  logoutUser,
  isAuthorizedAdminEmail,
  recordScanInDb,
  testFirestoreConnection,
} from '../services/firebase';

interface AuthContextType {
  currentUser: FirebaseUser | null;
  userProfile: UserProfile | null;
  isAdmin: boolean;
  isLoading: boolean;
  guestScansUsed: number;
  guestScansRemaining: number;
  isUnlimited: boolean;
  canScan: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
  recordScanUsage: (scanData: {
    url: string;
    defangedUrl: string;
    verdict: string;
    probability: number;
    riskLevel: string;
  }) => Promise<boolean>;
  openAuthModal: (mode?: 'login' | 'register') => void;
  closeAuthModal: () => void;
  isAuthModalOpen: boolean;
  authModalMode: 'login' | 'register';
  isLimitModalOpen: boolean;
  closeLimitModal: () => void;
}

const GUEST_SCAN_LIMIT = 10;
const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<FirebaseUser | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login');
  const [isLimitModalOpen, setIsLimitModalOpen] = useState(false);

  // Track guest scans in localStorage
  const [guestScansUsed, setGuestScansUsed] = useState<number>(() => {
    try {
      const stored = localStorage.getItem('phishguard_guest_scans_count');
      return stored ? parseInt(stored, 10) : 0;
    } catch {
      return 0;
    }
  });

  // Listen to Firebase Auth state
  useEffect(() => {
    testFirestoreConnection();

    const unsubscribe = onAuthStateChanged(auth, async (user) => {
      setCurrentUser(user);
      if (user) {
        const profile = await fetchUserProfile(user.uid);
        setUserProfile(profile);
      } else {
        setUserProfile(null);
      }
      setIsLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const isUnlimited = !!currentUser;
  const guestScansRemaining = Math.max(0, GUEST_SCAN_LIMIT - guestScansUsed);
  const canScan = isUnlimited || guestScansRemaining > 0;

  const isAdmin =
    (currentUser && isAuthorizedAdminEmail(currentUser.email)) ||
    userProfile?.role === 'admin' ||
    false;

  const login = async (email: string, pass: string) => {
    const profile = await loginWithEmail(email, pass);
    setUserProfile(profile);
    setIsAuthModalOpen(false);
  };

  const register = async (email: string, pass: string, name: string) => {
    const profile = await registerWithEmail(email, pass, name);
    setUserProfile(profile);
    setIsAuthModalOpen(false);
  };

  const logout = async () => {
    await logoutUser();
    setCurrentUser(null);
    setUserProfile(null);
  };

  const recordScanUsage = async (scanData: {
    url: string;
    defangedUrl: string;
    verdict: string;
    probability: number;
    riskLevel: string;
  }): Promise<boolean> => {
    if (!canScan) {
      setIsLimitModalOpen(true);
      return false;
    }

    if (!isUnlimited) {
      const nextCount = guestScansUsed + 1;
      setGuestScansUsed(nextCount);
      try {
        localStorage.setItem('phishguard_guest_scans_count', nextCount.toString());
      } catch {}
    }

    // Persist scan in Firestore
    await recordScanInDb({
      ...scanData,
      userId: currentUser?.uid || 'guest',
      userEmail: currentUser?.email || 'guest@anonymous',
    });

    // Update local profile scans counter if logged in
    if (userProfile) {
      setUserProfile((prev) => (prev ? { ...prev, totalScans: prev.totalScans + 1 } : null));
    }

    return true;
  };

  const openAuthModal = (mode: 'login' | 'register' = 'login') => {
    setAuthModalMode(mode);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => setIsAuthModalOpen(false);
  const closeLimitModal = () => setIsLimitModalOpen(false);

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        userProfile,
        isAdmin,
        isLoading,
        guestScansUsed,
        guestScansRemaining,
        isUnlimited,
        canScan,
        login,
        register,
        logout,
        recordScanUsage,
        openAuthModal,
        closeAuthModal,
        isAuthModalOpen,
        authModalMode,
        isLimitModalOpen,
        closeLimitModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
