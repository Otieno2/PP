export interface User {
  uid: string;
  email: string;
  displayName?: string;
  phoneNumber?: string;
  balance: number;
  rewardPoints?: number;
  premiumStatus: boolean;
  premiumPlan?: string;
  premiumExpiry?: Date;
  createdAt: Date;
}

export interface UserProfile {
  fullName: string;
  email: string;
  phoneNumber: string;
  profilePicture?: string;
  dateOfBirth?: string;
  address?: string;
  idNumber?: string;
  verified: boolean;
}

export interface WithdrawalMethod {
  id: string;
  type: 'bank' | 'mobile' | 'card';
  name: string;
  details: BankDetails | MobileDetails | CardDetails;
  isDefault: boolean;
  verified: boolean;
  createdAt: Date;
}

export interface BankDetails {
  bankName: string;
  accountNumber: string;
  accountHolderName: string;
  bankCountry?: string;
  swiftCode?: string;
  ibanCode?: string;
}

export interface MobileDetails {
  phoneNumber: string;
  provider: 'mpesa' | 'airtel' | 'mtn';
  accountName: string;
}

export interface CardDetails {
  cardType: 'visa' | 'mastercard';
  cardNumber: string; // masked
  expiryDate: string;
  cardHolderName: string;
}

export interface Transaction {
  id: string;
  uid: string;
  type: 'send' | 'receive' | 'airtime' | 'data' | 'reward' | 'deposit' | 'withdrawal' | 'savings_deposit' | 'savings_withdrawal' | 'savings_interest' | 'referral_bonus' | 'subscription' | 'loan_disbursement' | 'loan_repayment';
  amount: number;
  fee?: number;
  netAmount?: number;
  description: string;
  timestamp: Date;
  status: 'pending' | 'completed' | 'failed';
  recipient?: string;
  sender?: string;
  method?: string;
  direction: '+' | '-';
  loanId?: string;
}

export interface SavingsAccount {
  id: string;
  uid: string;
  principal: number;
  lockPeriod: number; // in months
  annualInterestRate: number;
  startDate: Date;
  maturityDate: Date;
  status: 'active' | 'matured' | 'withdrawn';
  currentValue?: number;
  earnedInterest?: number;
  hasActiveLoan?: boolean;
}

export interface Loan {
  id: string;
  uid: string;
  savingsAccountId: string;
  amount: number;
  interestRate: number;
  totalInterest: number;
  totalRepayment: number;
  disbursementDate: Date;
  dueDate: Date;
  status: 'active' | 'repaid' | 'overdue' | 'defaulted';
  repaidAmount: number;
  remainingAmount: number;
  autoDeductFromSavings: boolean;
  createdAt: Date;
}

export interface PremiumSubscription {
  uid: string;
  isActive: boolean;
  plan: 'basic' | 'plus' | 'vip';
  startDate: Date;
  expiryDate: Date;
  lastPayment: number;
  autoRenew: boolean;
}

export interface FeeBreakdown {
  percentageFee: number;
  fixedFee: number;
  totalFee: number;
  netAmount: number;
  feeRule: any;
  premiumDiscount?: number;
}

export interface PlatformStats {
  totalUsers: number;
  activeUsers: number;
  premiumUsers: number;
  totalTransactions: number;
  totalVolume: number;
  averageTransactionSize: number;
  conversionRate: number;
  totalSavings: number;
  totalLoansIssued: number;
  totalLoanValue: number;
  overdueLoans: number;
  totalExpenses: number;
  aiAssistantUsage: number;
}