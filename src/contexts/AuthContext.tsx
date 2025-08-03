import React, { createContext, useContext, useEffect, useState } from 'react';
import { auth as firebaseAuth, GoogleAuthProvider, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, signInWithPopup, onAuthStateChanged } from '../config/firebase';

// Mock User interface to match Firebase User
interface MockUser {
  uid: string;
  email: string | null;
  displayName: string | null;
}

interface AuthContextType {
  currentUser: MockUser | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Mock authentication for development
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<MockUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Use Firebase onAuthStateChanged to manage user session
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(firebaseAuth, (user) => {
      if (user) {
        // User is signed in
        // Handle temp email users (phone registrations)
        const displayEmail = user.email?.includes('@phantompay.temp') 
          ? user.email.replace('@phantompay.temp', '') 
          : user.email;
        
        setCurrentUser({
          uid: user.uid,
          email: displayEmail,
          displayName: user.displayName
        });
        // For demo purposes, also store in localStorage to simulate persistence across browser restarts
        localStorage.setItem('phantompay_user', JSON.stringify({ uid: user.uid, email: displayEmail, displayName: user.displayName }));
      } else {
        // User is signed out
        setCurrentUser(null);
        localStorage.removeItem('phantompay_user');
      }
      setLoading(false);
    });

    // Cleanup subscription on unmount
    return () => unsubscribe();
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const userCredential = await signInWithEmailAndPassword(firebaseAuth, email, password);
      // currentUser will be set by onAuthStateChanged listener
    } catch (error) {
      setLoading(false);
      throw error; // Re-throw to be caught by UI
    }
  };

  const register = async (email: string, password: string) => {
    setLoading(true);
    try {
      const userCredential = await createUserWithEmailAndPassword(firebaseAuth, email, password);
      // currentUser will be set by onAuthStateChanged listener
    } catch (error) {
      setLoading(false);
      throw error;
    }
  };

  const loginWithGoogle = async () => {
    setLoading(true);
    try {
      const provider = new GoogleAuthProvider();
      const userCredential = await signInWithPopup(firebaseAuth, provider);
      // currentUser will be set by onAuthStateChanged listener
    } catch (error) {
      setLoading(false);
      throw error;
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await signOut(firebaseAuth);
      // currentUser will be set to null by onAuthStateChanged listener
    } catch (error) {
      setLoading(false);
      throw error;
    }
  };

  // Fallback for initial load if onAuthStateChanged hasn't fired yet but localStorage has a user
  // This helps prevent flickering if the user was already logged in
  useEffect(() => {
    if (loading && !currentUser) {
      const savedUser = localStorage.getItem('phantompay_user');
      if (savedUser) {
        try {
          const parsedUser = JSON.parse(savedUser);
          setCurrentUser(parsedUser);
        } catch (e) {
          console.error("Failed to parse user from localStorage", e);
        }
      }
    }
  }, [loading, currentUser]);

  const value = {
    currentUser,
    login,
    register,
    loginWithGoogle,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};