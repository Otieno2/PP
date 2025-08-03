import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Eye, EyeOff, Wallet, Mail, Lock, CheckCircle, ArrowLeft, Phone } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';

interface LoginForm {
  email: string;
  password: string;
}

interface RegisterForm {
  registrationMethod: 'email' | 'phone';
  email?: string;
  phoneNumber?: string;
  password: string;
  confirmPassword: string;
}

interface VerificationForm {
  verificationCode: string;
}

const LoginPage: React.FC = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [registrationMethod, setRegistrationMethod] = useState<'email' | 'phone'>('email');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [registrationStep, setRegistrationStep] = useState<'form' | 'verification'>('form');
  const [pendingContact, setPendingContact] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  
  const { currentUser, login, register, loginWithGoogle } = useAuth();
  
  const loginForm = useForm<LoginForm>();
  const registerForm = useForm<RegisterForm>({
    defaultValues: {
      registrationMethod: 'email'
    }
  });
  const verificationForm = useForm<VerificationForm>();

  if (currentUser) {
    return <Navigate to="/" replace />;
  }

  const generateVerificationCode = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  };

  const sendVerificationCode = async (contact: string, method: 'email' | 'phone', code: string) => {
    // Simulate sending verification code - in production, this would call your email/SMS service
    if (method === 'email') {
      console.log(`Sending verification email to ${contact} with code: ${code}`);
      toast.success(`Verification code sent to ${contact}! Check your inbox.`);
    } else {
      console.log(`Sending verification SMS to ${contact} with code: ${code}`);
      toast.success(`Verification code sent to ${contact}! Check your messages.`);
    }
    
    // Store the code temporarily (in production, store in backend)
    localStorage.setItem(`verification_${contact}`, JSON.stringify({
      code,
      timestamp: Date.now(),
      expires: Date.now() + 10 * 60 * 1000 // 10 minutes
    }));

    // Simulate email sending delay
    await new Promise(resolve => setTimeout(resolve, 1000));
  };

  const onLoginSubmit = async (data: LoginForm) => {
    setLoading(true);
    try {
      await login(data.email, data.password);
      toast.success('Welcome back!');
    } catch (error: any) {
      toast.error(error.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const onRegisterSubmit = async (data: RegisterForm) => {
    setLoading(true);
    try {
      const contact = data.registrationMethod === 'email' ? data.email! : data.phoneNumber!;
      
      // Generate and send verification code
      const code = generateVerificationCode();
      await sendVerificationCode(contact, data.registrationMethod, code);
      
      // Store registration data temporarily
      localStorage.setItem(`pending_registration_${contact}`, JSON.stringify({
        registrationMethod: data.registrationMethod,
        email: data.email,
        phoneNumber: data.phoneNumber,
        password: data.password,
        timestamp: Date.now()
      }));
      
      setPendingContact(contact);
      setRegistrationStep('verification');
      
    } catch (error: any) {
      toast.error(error.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const onVerificationSubmit = async (data: VerificationForm) => {
    setLoading(true);
    try {
      // Verify the code
      const storedData = localStorage.getItem(`verification_${pendingContact}`);
      if (!storedData) {
        throw new Error('Verification code expired. Please try again.');
      }

      const { code, expires } = JSON.parse(storedData);
      
      if (Date.now() > expires) {
        localStorage.removeItem(`verification_${pendingContact}`);
        throw new Error('Verification code expired. Please try again.');
      }

      if (data.verificationCode !== code) {
        throw new Error('Invalid verification code. Please try again.');
      }

      // Get pending registration data
      const pendingData = localStorage.getItem(`pending_registration_${pendingContact}`);
      if (!pendingData) {
        throw new Error('Registration data not found. Please start over.');
      }

      const { registrationMethod, email, phoneNumber, password } = JSON.parse(pendingData);

      // Complete registration - use email for Firebase Auth (create temp email for phone users)
      const authEmail = registrationMethod === 'email' ? email : `${phoneNumber.replace(/\D/g, '')}@phantompay.temp`;
      await register(authEmail, password);
      
      // Clean up temporary data
      localStorage.removeItem(`verification_${pendingContact}`);
      localStorage.removeItem(`pending_registration_${pendingContact}`);
      
      toast.success('Account created successfully! Welcome to PhantomPay! 🎉');
      
    } catch (error: any) {
      toast.error(error.message || 'Verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    if (!pendingContact) return;
    
    setLoading(true);
    try {
      const code = generateVerificationCode();
      const method = pendingContact.includes('@') ? 'email' : 'phone';
      await sendVerificationCode(pendingContact, method, code);
    } catch (error: any) {
      toast.error('Failed to resend code');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToRegistration = () => {
    setRegistrationStep('form');
    setPendingContact('');
    setVerificationCode('');
  };

  const handleGoogleLogin = async () => {
    setLoading(true);
    try {
      await loginWithGoogle();
      toast.success('Welcome!');
    } catch (error: any) {
      toast.error(error.message || 'Google sign-in failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-indigo-900 to-blue-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center items-center space-x-3 mb-6">
            <div className="bg-white p-3 rounded-2xl shadow-lg">
              <Wallet className="h-12 w-12 text-purple-600" />
            </div>
          </div>
          <h2 className="text-4xl font-bold text-white mb-2">
            PhantomPay
          </h2>
          <p className="text-purple-200 text-lg">
            Your secure digital wallet
          </p>
        </div>

        {/* Main Form Container */}
        <div className="bg-white rounded-2xl shadow-2xl p-8">
          {/* Login Form */}
          {isLogin && (
            <>
              <div className="mb-6">
                <h3 className="text-2xl font-bold text-gray-900 text-center">
                  Welcome Back
                </h3>
                <p className="text-gray-600 text-center mt-2">
                  Sign in to your account
                </p>
              </div>

              <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className="space-y-6">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                    Email Address
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Mail className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...loginForm.register('email', { 
                        required: 'Email is required',
                        pattern: {
                          value: /^\S+@\S+$/i,
                          message: 'Invalid email address'
                        }
                      })}
                      type="email"
                      className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                      placeholder="Enter your email"
                    />
                  </div>
                  {loginForm.formState.errors.email && (
                    <p className="mt-1 text-sm text-red-600">{loginForm.formState.errors.email.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...loginForm.register('password', { 
                        required: 'Password is required'
                      })}
                      type={showPassword ? 'text' : 'password'}
                      className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      ) : (
                        <Eye className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      )}
                    </button>
                  </div>
                  {loginForm.formState.errors.password && (
                    <p className="mt-1 text-sm text-red-600">{loginForm.formState.errors.password.message}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                >
                  {loading ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                      Signing In...
                    </div>
                  ) : (
                    'Sign In'
                  )}
                </button>
              </form>
            </>
          )}

          {/* Registration Form */}
          {!isLogin && registrationStep === 'form' && (
            <>
              <div className="mb-6">
                <h3 className="text-2xl font-bold text-gray-900 text-center">
                  Create Account
                </h3>
                <p className="text-gray-600 text-center mt-2">
                  Join PhantomPay today
                </p>
              </div>

              <form onSubmit={registerForm.handleSubmit(onRegisterSubmit)} className="space-y-6">
                {/* Registration Method Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">
                    How would you like to register?
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <label className={`flex items-center p-3 border rounded-lg cursor-pointer transition-colors ${
                      registrationMethod === 'email' ? 'border-purple-500 bg-purple-50' : 'border-gray-300 hover:border-purple-300'
                    }`}>
                      <input
                        {...registerForm.register('registrationMethod')}
                        type="radio"
                        value="email"
                        onChange={() => setRegistrationMethod('email')}
                        className="sr-only"
                      />
                      <div className="flex items-center">
                        <Mail className="h-4 w-4 text-purple-600 mr-2" />
                        <div>
                          <p className="font-medium text-gray-900">Email</p>
                          <p className="text-xs text-gray-600">Use email address</p>
                        </div>
                      </div>
                    </label>
                    <label className={`flex items-center p-3 border rounded-lg cursor-pointer transition-colors ${
                      registrationMethod === 'phone' ? 'border-purple-500 bg-purple-50' : 'border-gray-300 hover:border-purple-300'
                    }`}>
                      <input
                        {...registerForm.register('registrationMethod')}
                        type="radio"
                        value="phone"
                        onChange={() => setRegistrationMethod('phone')}
                        className="sr-only"
                      />
                      <div className="flex items-center">
                        <Phone className="h-4 w-4 text-purple-600 mr-2" />
                        <div>
                          <p className="font-medium text-gray-900">Phone</p>
                          <p className="text-xs text-gray-600">Use phone number</p>
                        </div>
                      </div>
                    </label>
                  </div>
                </div>

                {/* Email Field */}
                {registrationMethod === 'email' && (
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                      Email Address
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Mail className="h-5 w-5 text-gray-400" />
                      </div>
                      <input
                        {...registerForm.register('email', { 
                          required: registrationMethod === 'email' ? 'Email is required' : false,
                          pattern: registrationMethod === 'email' ? {
                            value: /^\S+@\S+$/i,
                            message: 'Invalid email address'
                          } : undefined
                        })}
                        type="email"
                        className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                        placeholder="Enter your email"
                      />
                    </div>
                    {registerForm.formState.errors.email && (
                      <p className="mt-1 text-sm text-red-600">{registerForm.formState.errors.email.message}</p>
                    )}
                  </div>
                )}

                {/* Phone Number Field */}
                {registrationMethod === 'phone' && (
                  <div>
                    <label htmlFor="phoneNumber" className="block text-sm font-medium text-gray-700 mb-2">
                      Phone Number
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Phone className="h-5 w-5 text-gray-400" />
                      </div>
                      <input
                        {...registerForm.register('phoneNumber', { 
                          required: registrationMethod === 'phone' ? 'Phone number is required' : false,
                          pattern: registrationMethod === 'phone' ? {
                            value: /^(\+254|0)[17]\d{8}$/,
                            message: 'Please enter a valid Kenyan phone number'
                          } : undefined
                        })}
                        type="tel"
                        className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                        placeholder="+254712345678 or 0712345678"
                      />
                    </div>
                    {registerForm.formState.errors.phoneNumber && (
                      <p className="mt-1 text-sm text-red-600">{registerForm.formState.errors.phoneNumber.message}</p>
                    )}
                  </div>
                )}

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...registerForm.register('password', { 
                        required: 'Password is required',
                        minLength: {
                          value: 6,
                          message: 'Password must be at least 6 characters'
                        }
                      })}
                      type={showPassword ? 'text' : 'password'}
                      className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      ) : (
                        <Eye className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      )}
                    </button>
                  </div>
                  {registerForm.formState.errors.password && (
                    <p className="mt-1 text-sm text-red-600">{registerForm.formState.errors.password.message}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-2">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...registerForm.register('confirmPassword', { 
                        required: 'Please confirm your password',
                        validate: (value) => {
                          const password = registerForm.watch('password');
                          return value === password || 'Passwords do not match';
                        }
                      })}
                      type={showConfirmPassword ? 'text' : 'password'}
                      className="block w-full pl-10 pr-10 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors"
                      placeholder="Confirm your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showConfirmPassword ? (
                        <EyeOff className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      ) : (
                        <Eye className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      )}
                    </button>
                  </div>
                  {registerForm.formState.errors.confirmPassword && (
                    <p className="mt-1 text-sm text-red-600">{registerForm.formState.errors.confirmPassword.message}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                >
                  {loading ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                      Sending Verification...
                    </div>
                  ) : (
                    'Create Account'
                  )}
                </button>
              </form>
            </>
          )}

          {/* Email Verification Step */}
          {!isLogin && registrationStep === 'verification' && (
            <>
              <div className="mb-6">
                <div className="flex items-center justify-center mb-4">
                  <div className="bg-green-100 p-3 rounded-full">
                    {pendingContact.includes('@') ? (
                      <Mail className="h-8 w-8 text-green-600" />
                    ) : (
                      <Phone className="h-8 w-8 text-green-600" />
                    )}
                  </div>
                </div>
                <h3 className="text-2xl font-bold text-gray-900 text-center">
                  {pendingContact.includes('@') ? 'Verify Your Email' : 'Verify Your Phone'}
                </h3>
                <p className="text-gray-600 text-center mt-2">
                  We've sent a 6-digit verification code {pendingContact.includes('@') ? 'to' : 'via SMS to'}
                </p>
                <p className="text-purple-600 font-medium text-center">
                  {pendingContact}
                </p>
              </div>

              <form onSubmit={verificationForm.handleSubmit(onVerificationSubmit)} className="space-y-6">
                <div>
                  <label htmlFor="verificationCode" className="block text-sm font-medium text-gray-700 mb-2">
                    Verification Code
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <CheckCircle className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...verificationForm.register('verificationCode', { 
                        required: 'Verification code is required',
                        pattern: {
                          value: /^\d{6}$/,
                          message: 'Please enter a valid 6-digit code'
                        }
                      })}
                      type="text"
                      maxLength={6}
                      className="block w-full pl-10 pr-3 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-600 focus:border-transparent transition-colors text-center text-lg font-mono tracking-widest"
                      placeholder="000000"
                    />
                  </div>
                  {verificationForm.formState.errors.verificationCode && (
                    <p className="mt-1 text-sm text-red-600">{verificationForm.formState.errors.verificationCode.message}</p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                >
                  {loading ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                      Verifying...
                    </div>
                  ) : (
                    'Verify & Create Account'
                  )}
                </button>
              </form>

              <div className="mt-6 space-y-3">
                <button
                  onClick={handleResendCode}
                  disabled={loading}
                  className="w-full text-purple-600 hover:text-purple-700 font-medium text-sm disabled:opacity-50"
                >
                  Didn't receive the code? Resend {pendingContact.includes('@') ? 'Email' : 'SMS'}
                </button>
                
                <button
                  onClick={handleBackToRegistration}
                  className="w-full flex items-center justify-center text-gray-600 hover:text-gray-700 font-medium text-sm"
                >
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Registration
                </button>
              </div>
            </>
          )}

          {/* Google Sign In - Only show for login or registration form */}
          {(isLogin || registrationStep === 'form') && (
            <>
              <div className="mt-6">
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-white text-gray-500">Or continue with</span>
                  </div>
                </div>

                <div className="mt-6">
                  <button
                    onClick={handleGoogleLogin}
                    disabled={loading}
                    className="w-full inline-flex justify-center py-3 px-4 border border-gray-300 rounded-lg shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    <svg className="h-5 w-5 mr-2" viewBox="0 0 24 24">
                      <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                      <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                      <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                      <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                  </button>
                </div>
              </div>

              <div className="mt-6 text-center">
                <button
                  onClick={() => {
                    setIsLogin(!isLogin);
                    setRegistrationStep('form');
                    setPendingContact('');
                  }}
                  className="text-sm text-purple-600 hover:text-purple-500 font-medium"
                >
                  {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default LoginPage;