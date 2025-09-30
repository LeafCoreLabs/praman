import React, { useState, useEffect } from 'react';
import requests from 'axios';
import { Power, ArrowLeft, Loader2, BarChart3, FilePlus, Search, Lock, User, Mail, Calendar, CheckCircle, XCircle } from 'lucide-react';

// Constants
const BACKEND_URL = "http://127.0.0.1:5000";
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// Helper Functions
const formatRole = (role) => {
    if (!role) return '';
    return role.charAt(0).toUpperCase() + role.slice(1);
};

// NEW: Helper to map UI name to DB role name
const getExpectedRole = (userType) => {
    if (userType === "Admin") return "admin";
    if (userType === "Institute / Issuer") return "institute";
    if (userType === "Organisation / Verifier") return "organisation";
    return null;
};

const formatDate = (isoString) => {
    if (!isoString) return 'N/A';
    try {
        const date = new Date(isoString);
        // Format as YYYY-MM-DD HH:mm (using zero-padding for single digits)
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}`;
    } catch {
        return isoString; // return raw string if date is invalid
    }
};

const getCurrentDate = () => {
    // Returns current date in YYYY-MM-DD format for max date attribute
    return new Date().toISOString().split('T')[0];
};

const PasswordRequirements = () => (
    <div className="text-xs text-gray-600 mt-1 p-2 bg-blue-100 rounded-md border border-blue-200">
        Password must be at least 8 characters long and contain:
        <ul className="list-disc list-inside mt-1 space-y-0.5">
            <li>One uppercase letter</li>
            <li>One number</li>
            <li>One special character (@, #, $, etc.)</li>
        </ul>
    </div>
);

// Main Application Component
const App = () => {
    // --- State Management ---
    const [step, setStep] = useState('user_type'); // 'user_type', 'login', 'signup', 'dashboard'
    const [token, setToken] = useState(null);
    const [role, setRole] = useState(null);
    const [userType, setUserType] = useState(null);
    const [message, setMessage] = useState({ type: null, text: null });
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('Dashboard');
    const [confirmLogout, setConfirmLogout] = useState(false);

    // Form states
    const [loginData, setLoginData] = useState({ username: '', password: '' });
    const [signupData, setSignupData] = useState({
        username: '', password: '', name: '', email: '', contact: '', address: '', designation: ''
    });
    const [issueData, setIssueData] = useState({
        student_name: '', roll_no: '', dob: '', course: '', college: '', date_of_issue: ''
    });
    const [verifyData, setVerifyData] = useState({
        student_name: '', roll_no: '', date_of_issue: ''
    });
    const [uploadedFile, setUploadedFile] = useState(null);
    const [verificationResult, setVerificationResult] = useState(null); // Stores successful verification data
    const [verifyError, setVerifyError] = useState(null); // Stores specific verification error text

    // Check for signup success flash message from previous session state
    useEffect(() => {
        if (sessionStorage.getItem('signup_success')) {
            setMessage({ type: 'success', text: 'Account created successfully! Please log in.' });
            sessionStorage.removeItem('signup_success');
        }
    }, []);

    // New useEffect to handle state resets when switching to the Verify tab (Fixes crash)
    useEffect(() => {
        if (activeTab === 'Verify Certificate') {
            // Reset all verification related states when entering the tab
            setVerifyData({ student_name: '', roll_no: '', date_of_issue: '' });
            setUploadedFile(null);
            setVerificationResult(null);
            setVerifyError(null);
            
            // Clear file input value
            const fileInput = document.getElementById('verifyFileInput');
            if (fileInput) {
                fileInput.value = '';
            }
            clearMessage();
        }
    }, [activeTab]);


    // --- Utility Handlers ---

    const handleFileInput = (event) => {
        const file = event.target.files[0];
        if (file && file.size > MAX_FILE_SIZE) {
            setMessage({ type: 'error', text: 'File size exceeds the 5MB limit.' });
            setUploadedFile(null);
        } else {
            setUploadedFile(file);
            setMessage({ type: null, text: null });
        }
    };

    const clearMessage = () => setMessage({ type: null, text: null });

    // --- Authentication Logic ---

    const handleLogin = async (e) => {
        e.preventDefault();
        clearMessage();
        if (!loginData.username || !loginData.password) {
            return setMessage({ type: 'error', text: 'Please enter both username and password.' });
        }

        // --- DEBUGGING LOG ADDED HERE ---
        console.log("Sending Login Payload:", {
            username: loginData.username,
            password: '[PASSWORD HIDDEN]',
            user_type: userType
        });
        // ---------------------------------

        setLoading(true);
        try {
            const response = await requests.post(`${BACKEND_URL}/login`, {
                username: loginData.username,
                password: loginData.password,
                user_type: userType
            });
            const data = response.data;

            // --- FIX: Role Restriction ---
            const expectedRole = getExpectedRole(userType);
            
            if (data.role !== expectedRole) {
                // Manually reject the login attempt if the selected portal doesn't match the actual role
                throw new Error(`Access denied. Login portal does not match user role (${data.role}).`);
            }
            // --- END FIX ---
            
            setToken(data.access_token);
            setRole(data.role);
            setStep('dashboard');
            setMessage({ type: 'success', text: 'Login successful!' });

        } catch (error) {
            const msg = error.response?.data?.error || (error.message.includes("Access denied") ? error.message : 'Login failed. Please check your credentials.');
            setMessage({ type: 'error', text: msg });
        } finally {
            setLoading(false);
        }
    };

    const validatePassword = (password) => {
        const specialCharacters = /[!@#$%^&*()<>?/|~:]/;
        if (password.length < 8) return "Password must be at least 8 characters long.";
        if (!/[A-Z]/.test(password)) return "Password must contain at least one capital letter.";
        if (!/[0-9]/.test(password)) return "Password must contain at least one number.";
        if (!specialCharacters.test(password)) return "Password must contain at least one special character.";
        return null;
    };

    const validateEmail = (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? null : "Please enter a valid email address.";
    };

    const handleSignup = async (e) => {
        e.preventDefault();
        clearMessage();

        const passwordError = validatePassword(signupData.password);
        if (!signupData.username) return setMessage({ type: 'error', text: 'Username is mandatory.' });
        if (passwordError) return setMessage({ type: 'error', text: passwordError });

        const emailError = validateEmail(signupData.email);
        if (emailError) return setMessage({ type: 'error', text: emailError });
        
        if (!signupData.name) return setMessage({ type: 'error', text: 'Full Name / Organization Name is mandatory.' });

        setLoading(true);
        try {
            const role_type = userType === "Institute / Issuer" ? "institute" : "organisation";
            const response = await requests.post(`${BACKEND_URL}/signup`, { ...signupData, role_type });

            setMessage({ type: 'success', text: 'Account created successfully! Please log in.' });
            setStep('login');
            // Removed sessionStorage logic, relying on state update for immediate display

        } catch (error) {
            const msg = error.response?.data?.error || 'Signup failed.';
            setMessage({ type: 'error', text: msg });
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        setToken(null);
        setRole(null);
        setUserType(null);
        setStep('user_type');
        setConfirmLogout(false);
        setLoginData({ username: '', password: '' });
        setMessage({ type: null, text: null });
        // Clear verification data on logout
        setVerifyData({ student_name: '', roll_no: '', date_of_issue: '' });
        setVerificationResult(null);
        setVerifyError(null);
        if (document.getElementById('verifyFileInput')) {
            document.getElementById('verifyFileInput').value = '';
        }
    };

    // --- Dashboard Content (Data Fetching) ---

    const DashboardContent = () => {
        const [fraudLogs, setFraudLogs] = useState([]);
        const [dashLoading, setDashLoading] = useState(true);
        
        useEffect(() => {
            if (role === 'admin' && token) {
                const fetchLogs = async () => {
                    setDashLoading(true);
                    try {
                        const response = await requests.get(`${BACKEND_URL}/fraud_logs`, {
                            headers: { Authorization: `Bearer ${token}` }
                        });
                        setFraudLogs(response.data);
                    } catch (error) {
                        setFraudLogs([]);
                        setMessage({ type: 'error', text: 'Failed to fetch fraud logs.' });
                    } finally {
                        setDashLoading(false);
                    }
                };
                fetchLogs();
            } else {
                setDashLoading(false);
            }
        }, [role, token]);

        if (dashLoading) {
            return <div className="text-center text-gray-700 py-10"><Loader2 className="animate-spin inline mr-2 h-6 w-6" /> Loading Dashboard...</div>;
        }

        if (role === 'admin') {
            return (
                <div>
                    <h3 className="text-xl font-semibold mb-4 text-gray-900">Fraud Log Summary</h3>
                    {fraudLogs.length > 0 ? (
                        <div className="overflow-x-auto bg-white border border-gray-300 rounded-lg shadow-lg">
                            <table className="min-w-full text-sm text-left text-gray-800">
                                <thead className="text-xs uppercase bg-blue-100 text-gray-700">
                                    <tr>
                                        <th scope="col" className="px-4 py-2">ID</th>
                                        <th scope="col" className="px-4 py-2">User/Source</th> {/* NEW: User/Source Column */}
                                        <th scope="col" className="px-4 py-2">Cert ID</th>
                                        <th scope="col" className="px-4 py-2">Tamper Score</th>
                                        <th scope="col" className="px-4 py-2">Reason</th>
                                        <th scope="col" className="px-4 py-2">Logged At</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {fraudLogs.map((log, index) => (
                                        <tr key={index} className="bg-white border-b border-gray-100 hover:bg-blue-50">
                                            <td className="px-4 py-2 font-medium">{log.id}</td>
                                            <td className="px-4 py-2 text-xs font-semibold text-blue-700">{log.username || 'Anonymous'}</td> {/* NEW: Display username (assuming backend returns it) */}
                                            <td className="px-4 py-2 truncate">{log.cert_id || 'N/A'}</td>
                                            <td className="px-4 py-2">{log.tamper_score}</td>
                                            <td className="px-4 py-2">{log.reason}</td>
                                            <td className="px-4 py-2 text-xs">{formatDate(log.logged_at)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="text-center text-gray-500 py-12 empty-state">
                            <div className="text-5xl mb-4">🛡️</div>
                            <p className="text-lg font-medium">System Integrity Confirmed.</p>
                            <p className="text-sm">No fraud attempts have been logged recently.</p>
                        </div>
                    )}
                </div>
            );
        } else {
            return <div className="text-center text-gray-500 py-12">Institute/Organisation dashboard coming soon...</div>;
        }
    };

    // --- Issue Certificate Logic ---

    const handleIssueCertificate = async (e) => {
        e.preventDefault();
        clearMessage();
        if (role !== 'institute') return setMessage({ type: 'error', text: 'Only institutes can issue certificates.' });

        const { student_name, roll_no, dob, course, college, date_of_issue } = issueData;
        if (!student_name || !roll_no || !dob || !course || !college || !uploadedFile) {
            return setMessage({ type: 'error', text: 'All fields and certificate file are mandatory.' });
        }

        setLoading(true);
        try {
            const formData = new FormData();
            Object.keys(issueData).forEach(key => formData.append(key, issueData[key]));
            formData.append('file', uploadedFile);

            const response = await requests.post(`${BACKEND_URL}/issue`, formData, {
                headers: { 
                    'Content-Type': 'multipart/form-data',
                    'Authorization': `Bearer ${token}` 
                }
            });

            // --- CRITICAL FIX: Extract and display Tx Hash/Cert ID ---
            const data = response.data;
            console.log("Backend Issue Response Data:", data); // DEBUGGING LINE
            
            const certId = data.cert_id || 'N/A';
            const txHash = data.tx_hash || 'N/A';
            
            // Generate display string safely
            // *** FIX IMPLEMENTED HERE: Using \n for line break in the message string ***
            const messageText = `Certificate Issued Successfully!\nID: ${certId}\nTx Hash: ${txHash}`;

            // Set success message including the crucial transaction details
            setMessage({ 
                type: 'success', 
                text: messageText
            });
            
            // Then clear form elements
            setIssueData({ 
                student_name: '', roll_no: '', dob: '', course: '', college: '', date_of_issue: ''
            });
            setUploadedFile(null); 
            if (document.getElementById('issueFileInput')) {
                document.getElementById('issueFileInput').value = '';
            }
            // --- END CRITICAL FIX ---
            
        } catch (error) {
            // Log error data for debug
            console.error("Issuance Error Details:", error.response?.data || error.message);
            const msg = error.response?.data?.error || 'Error issuing certificate. Check console for details.';
            setMessage({ type: 'error', text: msg });
        } finally {
            setLoading(false);
        }
    };

    // --- Verify Certificate Logic ---

    const handleVerifyCertificate = async (e) => {
        e.preventDefault();
        clearMessage();
        setVerificationResult(null); // Clear previous results
        setVerifyError(null); // Clear previous specific error

        const { student_name, roll_no, date_of_issue } = verifyData;
        if (!student_name) {
            return setMessage({ type: 'error', text: 'Student Name is mandatory.' });
        }
        if (!roll_no && !date_of_issue) {
            return setMessage({ type: 'error', text: 'Provide either Roll Number or Date of Issue.' });
        }
        if (!uploadedFile) {
            return setMessage({ type: 'error', text: 'Certificate file is mandatory for verification.' });
        }

        setLoading(true);
        try {
            const formData = new FormData();
            formData.append('student_name', student_name);
            if (roll_no) formData.append('roll_no', roll_no);
            if (date_of_issue) formData.append('date_of_issue', date_of_issue);
            formData.append('file', uploadedFile);

            // START OF FRAUD TRACKING FIX (Sending token if logged in)
            const headers = { 'Content-Type': 'multipart/form-data' };
            if (token) {
                // Pass the token if the user is logged in, allowing the backend to log their ID.
                headers['Authorization'] = `Bearer ${token}`;
            }
            // END OF FRAUD TRACKING FIX
            
            const response = await requests.post(`${BACKEND_URL}/verify`, formData, {
                headers: headers
            });

            if (response.data.status === 'valid') {
                setVerificationResult(response.data); // Store full valid data
                setMessage({ type: 'success', text: 'Certificate Verified Successfully! Document is authentic.' });
            } 
            // In case the backend returns 200 but status is not 'valid' (shouldn't happen with current backend code)
            else {
                setMessage({ type: 'error', text: 'Verification failed with an unexpected status.' });
            }
            console.log("Verify Response:", response.data);

        } catch (error) {
            setVerificationResult(null);
            let errorReason = 'Backend not reachable or verification failed.';

            const status = error.response?.status;
            const statusText = error.response?.data?.status;

            if (status === 404 && statusText === 'tampered or invalid') {
                // Heuristic check to provide the specific message requested by the user
                // If the user provided both auxiliary details, assume the document hash was found, but the details didn't match.
                if (roll_no && date_of_issue) {
                    setVerifyError('Incorrect student details (Data Mismatch)');
                    errorReason = 'Verification Failed: Incorrect student details.';
                } else {
                    // Otherwise, assume the document hash itself was not found in the database/blockchain.
                    setVerifyError('Certificate not found on server (Hash Mismatch)');
                    errorReason = 'Verification Failed: Certificate not found on server.';
                }
            } else if (error.response?.data?.error) {
                errorReason = error.response.data.error;
            }

            setMessage({ type: 'error', text: errorReason });
        } finally {
            setLoading(false);
        }
    };

    // --- Verification Result Display Component ---
    const renderVerificationResult = () => {
        if (loading) return null;

        if (verificationResult) {
            // Success case: display metadata
            const data = verificationResult;
            const metadataKeys = [
                { key: 'cert_id', label: 'Certificate ID' },
                { key: 'student_name', label: 'Student Name' },
                { key: 'roll_no', label: 'Roll Number' },
                { key: 'dob', label: 'Date of Birth' },
                { key: 'course', label: 'Course' },
                { key: 'college', label: 'College / Institute' },
                { key: 'date_of_issue', label: 'Date of Issue' },
                { key: 'tx_hash', label: 'Blockchain Transaction Hash' },
            ];
            
            return (
                <div className="bg-green-50 border border-green-300 rounded-xl p-6 mt-6 shadow-md animate-in fade-in duration-500">
                    <h4 className="text-xl font-bold text-green-700 mb-4 flex items-center">
                        <CheckCircle className="w-6 h-6 mr-3" /> VERIFICATION SUCCESSFUL
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        {metadataKeys.map(item => (
                            <div key={item.key} className="p-3 bg-white border border-green-200 rounded-lg">
                                <span className="font-semibold text-green-600 block">{item.label}</span>
                                <span className="text-gray-800 break-words block mt-0.5">{data[item.key] || 'N/A'}</span>
                            </div>
                        ))}
                    </div>
                </div>
            );
        }
        
        if (verifyError) {
            // Specific failure case
            const isHashMismatch = verifyError.includes('Hash Mismatch');
            const icon = isHashMismatch ? '🔍' : '❌';
            
            return (
                <div className={`border rounded-xl p-6 mt-6 shadow-md animate-in fade-in duration-500 ${isHashMismatch ? 'bg-red-50 border-red-300' : 'bg-yellow-50 border-yellow-300'}`}>
                    <h4 className="text-xl font-bold text-gray-800 mb-4 flex items-center">
                        <span className="mr-3 text-2xl">{icon}</span> VERIFICATION FAILED
                    </h4>
                    <p className={`font-medium text-lg ${isHashMismatch ? 'text-red-700' : 'text-yellow-800'}`}>
                        {verifyError.split('(')[0].trim()}
                    </p>
                    <p className="text-sm text-gray-600 mt-2">
                        Please check the provided file and student details. All failed attempts are automatically logged.
                    </p>
                </div>
            );
        }
        
        return null;
    };


    // --- Rendering Logic ---

    const renderMessage = () => {
        if (!message.text) return null;

        const baseClasses = "p-3 mt-4 rounded-lg shadow-lg text-sm flex items-start mb-4 whitespace-pre-wrap"; // ADDED whitespace-pre-wrap
        const successClasses = "bg-green-600 text-white";
        const errorClasses = "bg-red-600 text-white";

        const classes = message.type === 'success' ? successClasses : errorClasses;
        const Icon = message.type === 'success' ? CheckCircle : XCircle;

        // Use pre-wrap to respect the \n line break
        return (
            <div className={`${baseClasses} ${classes} animate-in fade-in duration-500`}>
                <Icon className="w-5 h-5 mr-3 mt-0.5" />
                {message.text}
            </div>
        );
    };

    const renderLoginForm = () => (
        <form onSubmit={handleLogin} className="space-y-4">
            <h3 className="text-2xl font-semibold text-gray-800">Sign In</h3>

            <div className="relative">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                    type="text"
                    placeholder="Username"
                    value={loginData.username}
                    onChange={(e) => setLoginData({ ...loginData, username: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                    required
                />
            </div>

            <div className="relative">
                <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                    type="password"
                    placeholder="Password"
                    value={loginData.password}
                    onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                    required
                />
            </div>

            <div className="flex justify-between space-x-4 pt-4">
                <button
                    type="button"
                    onClick={() => { // Reset login credentials on going back
                        setUserType(null);
                        setLoginData({ username: '', password: '' }); 
                        setStep('user_type');
                        clearMessage(); // FIX: Clear message on back navigation
                    }}
                    className="btn w-full bg-gray-200 text-gray-700 hover:bg-gray-300 transition duration-200 flex items-center justify-center py-2.5"
                >
                    <ArrowLeft className="w-5 h-5 mr-2" /> Back
                </button>
                <button
                    type="submit"
                    disabled={loading}
                    className="btn w-full bg-blue-600 text-white hover:bg-blue-700 transition duration-200 flex items-center justify-center py-2.5"
                >
                    {loading ? <Loader2 className="animate-spin w-5 h-5" /> : 'Sign In'}
                </button>
            </div>
        </form>
    );

    const renderSignupForm = () => (
        <form onSubmit={handleSignup} className="space-y-4">
            <h3 className="text-2xl font-semibold text-gray-800">Create Account</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="relative col-span-2">
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                    <input
                        type="text"
                        placeholder="Username"
                        value={signupData.username}
                        onChange={(e) => setSignupData({ ...signupData, username: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                        required
                    />
                </div>
                <div className="relative col-span-2">
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                    <input
                        type="password"
                        placeholder="Password"
                        value={signupData.password}
                        onChange={(e) => setSignupData({ ...signupData, password: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                        required
                    />
                </div>
            </div>
            <PasswordRequirements />
            <div className="relative">
                <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                <input
                    type="text"
                    placeholder="Full Name / Organisation Name"
                    value={signupData.name}
                    onChange={(e) => setSignupData({ ...signupData, name: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                    required
                />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="relative">
                    <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                    <input
                        type="email"
                        placeholder="Email"
                        value={signupData.email}
                        onChange={(e) => setSignupData({ ...signupData, email: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                        required
                    />
                </div>
                <input
                    type="text"
                    placeholder="Contact Number"
                    value={signupData.contact}
                    onChange={(e) => setSignupData({ ...signupData, contact: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
                />
            </div>

            <textarea
                placeholder="Address"
                value={signupData.address}
                onChange={(e) => setSignupData({ ...signupData, address: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-xl py-3 px-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200 h-24"
            />
            
            <input
                type="text"
                placeholder="Designation / Role"
                value={signupData.designation}
                onChange={(e) => setSignupData({ ...signupData, designation: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4 focus:ring-2 focus:ring-blue-500 outline-none transition duration-200"
            />

            <button
                type="submit"
                disabled={loading}
                className="btn w-full bg-green-600 text-white hover:bg-green-700 transition duration-200 flex items-center justify-center py-3 mt-6"
            >
                {loading ? <Loader2 className="animate-spin w-5 h-5" /> : 'Create Account'}
            </button>
        </form>
    );

    const renderIssueForm = () => (
        <form onSubmit={handleIssueCertificate} className="space-y-4 p-6 bg-white rounded-xl border border-blue-200 shadow-xl">
            <h3 className="text-2xl font-semibold text-gray-800 mb-6">Issue Certificate (Institute)</h3>
            
            <input
                type="text"
                placeholder="Student Name"
                value={issueData.student_name}
                onChange={(e) => setIssueData({ ...issueData, student_name: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                required
            />
            <input
                type="text"
                placeholder="Roll Number / ID"
                value={issueData.roll_no}
                onChange={(e) => setIssueData({ ...issueData, roll_no: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                required
            />
            
            <div className="flex space-x-4">
                <div className="flex-1 relative">
                    <label htmlFor="issueDOB" className="block text-gray-700 font-medium text-xs mb-1">Date of Birth</label>
                    <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500 mt-2" />
                    <input
                        type="date"
                        id="issueDOB"
                        value={issueData.dob}
                        onChange={(e) => setIssueData({ ...issueData, dob: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 appearance-none"
                        max={getCurrentDate()}
                        required
                    />
                </div>
                <div className="flex-1 relative">
                    <label htmlFor="issueDate" className="block text-gray-700 font-medium text-xs mb-1">Date of Issue</label>
                    <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500 mt-2" />
                    <input
                        type="date"
                        id="issueDate"
                        value={issueData.date_of_issue}
                        onChange={(e) => setIssueData({ ...issueData, date_of_issue: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 appearance-none"
                        max={getCurrentDate()}
                        required
                    />
                </div>
            </div>

            <input
                type="text"
                placeholder="Course / Degree"
                value={issueData.course}
                onChange={(e) => setIssueData({ ...issueData, course: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                required
            />
            <input
                type="text"
                placeholder="College / Institute"
                value={issueData.college}
                onChange={(e) => setIssueData({ ...issueData, college: e.target.value })}
                className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                required
            />

            <label className="block text-gray-700 font-medium pt-2">Upload Certificate File (PDF/Image, max 5MB)</label>
            <input
                type="file"
                id="issueFileInput" // Added ID for clearing
                accept=".pdf,.jpg,.jpeg,.png"
                onChange={handleFileInput}
                className="w-full text-gray-600 bg-gray-100 rounded-lg p-2 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700 transition duration-200"
                required
            />
            
            <button
                type="submit"
                disabled={loading}
                className="btn w-full bg-green-600 text-white hover:bg-green-700 transition duration-200 flex items-center justify-center py-3 mt-6"
            >
                {loading ? <Loader2 className="animate-spin w-5 h-5" /> : 'Issue Certificate'}
            </button>
        </form>
    );

    const renderVerifyForm = () => {
        // NOTE: The inner useEffect has been moved to the top level of the App component (around line 72)
        // to comply with React's Rules of Hooks and fix the compilation crash.

        return (
            <form onSubmit={handleVerifyCertificate} className="space-y-4 p-6 bg-white rounded-xl border border-blue-200 shadow-xl">
                <h3 className="text-2xl font-semibold text-gray-800 mb-6">Verify Certificate (Organization)</h3>
                
                <div className="p-3 mb-4 text-sm rounded-lg bg-yellow-100 text-yellow-800 border border-yellow-400">
                    Student Name is mandatory. Provide **Roll Number OR Date of Issue** for verification.
                </div>

                <input
                    type="text"
                    placeholder="Student Name"
                    value={verifyData.student_name}
                    onChange={(e) => setVerifyData({ ...verifyData, student_name: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                    required
                />
                <input
                    type="text"
                    placeholder="Roll Number (Optional, or required if Date of Issue is empty)"
                    value={verifyData.roll_no}
                    onChange={(e) => setVerifyData({ ...verifyData, roll_no: e.target.value })}
                    className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 px-4"
                />
                
                {/* BUG FIX 2: Added explicit label for Date of Issue */}
                <label htmlFor="verifyDateOfIssue" className="block text-gray-700 font-medium text-sm pt-2 mb-1">Date of Issue (Optional, or Roll No. alternative)</label>
                <div className="relative">
                    <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
                    <input
                        type="date"
                        id="verifyDateOfIssue"
                        value={verifyData.date_of_issue}
                        onChange={(e) => setVerifyData({ ...verifyData, date_of_issue: e.target.value })}
                        className="w-full bg-white text-gray-800 placeholder-gray-500 border border-gray-300 rounded-full py-3 pl-12 pr-4 appearance-none"
                        max={getCurrentDate()}
                    />
                </div>
                

                <label className="block text-gray-700 font-medium pt-2">Upload Certificate File (PDF/Image, max 5MB)</label>
                <input
                    type="file"
                    id="verifyFileInput" // Added ID for clearing on reset
                    accept=".pdf,.jpg,.jpeg,.png"
                    onChange={handleFileInput}
                    className="w-full text-gray-600 bg-gray-100 rounded-lg p-2 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700 transition duration-200"
                    required
                />
                
                <button
                    type="submit"
                    disabled={loading}
                    className="btn w-full bg-blue-600 text-white hover:bg-blue-700 transition duration-200 flex items-center justify-center py-3 mt-6"
                >
                    {loading ? <Loader2 className="animate-spin w-5 h-5" /> : 'Verify Certificate'}
                </button>

                {renderVerificationResult()}
            </form>
        );
    };

    const renderDashboard = () => (
        <div className="text-gray-900">
            <div className="flex justify-between items-center mb-6">
                <h2 className="text-3xl font-bold">Welcome, {formatRole(role)}!</h2>
                <div className="w-48">
                    {confirmLogout ? (
                        <div className="bg-red-200 p-3 rounded-lg shadow-xl border border-red-300 text-red-800">
                            <p className="text-sm font-semibold mb-2">Are you sure?</p>
                            <div className="flex space-x-2">
                                <button
                                    onClick={handleLogout}
                                    className="flex-1 text-xs py-1.5 bg-red-600 text-white hover:bg-red-700 rounded-md transition duration-200"
                                >
                                    Yes, Logout
                                </button>
                                <button
                                    onClick={() => setConfirmLogout(false)}
                                    className="flex-1 text-xs py-1.5 bg-gray-400 text-gray-800 hover:bg-gray-500 rounded-md transition duration-200"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    ) : (
                        <button
                            onClick={() => setConfirmLogout(true)}
                            className="w-full flex items-center justify-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-lg shadow-md transition duration-200"
                        >
                            <Power className="w-5 h-5 mr-2" /> Logout
                        </button>
                    )}
                </div>
            </div>
            
            {/* FIX: RENDER MESSAGE HERE */}
            {renderMessage()}

            <div className="flex justify-center mb-8">
                <div className="flex space-x-2 bg-gray-200 p-1 rounded-full shadow-inner">
                    {['Dashboard', 'Issue Certificate', 'Verify Certificate'].filter(option => 
                        (option === 'Issue Certificate' && role === 'institute') || 
                        (option === 'Verify Certificate' && (role === 'institute' || role === 'organisation' || role === 'admin')) || 
                        (option === 'Dashboard')
                    ).map(option => (
                        <button
                            key={option}
                            onClick={() => setActiveTab(option)}
                            className={`flex items-center px-4 py-2 rounded-full font-medium transition duration-200 ${
                                activeTab === option 
                                    ? 'bg-blue-600 text-white shadow-xl' 
                                    : 'text-gray-600 hover:bg-gray-300'
                            }`}
                        >
                            {option === 'Dashboard' && <BarChart3 className="w-5 h-5 mr-2" />}
                            {option === 'Issue Certificate' && <FilePlus className="w-5 h-5 mr-2" />}
                            {option === 'Verify Certificate' && <Search className="w-5 h-5 mr-2" />}
                            {option}
                        </button>
                    ))}
                </div>
            </div>

            <div className="min-h-[50vh] pt-4">
                {activeTab === 'Dashboard' && <DashboardContent />}
                {activeTab === 'Issue Certificate' && renderIssueForm()}
                {activeTab === 'Verify Certificate' && renderVerifyForm()}
            </div>
        </div>
    );

    // --- Main Renderer ---

    const renderContent = () => {
        switch (step) {
            case 'user_type':
                return (
                    <div className="space-y-6">
                        <h3 className="text-2xl font-semibold text-gray-900">Welcome to Pramān</h3>
                        <p className="text-gray-700">Select your user type to proceed:</p>
                        <div className="flex flex-col space-y-4">
                            {["Admin", "Institute / Issuer", "Organisation / Verifier"].map(type => (
                                <button
                                    key={type}
                                    onClick={() => setUserType(type)}
                                    className={`w-full py-3 px-4 rounded-lg font-medium transition duration-200 ${
                                        userType === type 
                                            ? 'bg-blue-600 text-white shadow-lg border border-blue-400' 
                                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                                    }`}
                                >
                                    {type}
                                </button>
                            ))}
                        </div>
                        <button
                            onClick={() => userType && setStep('login')}
                            disabled={!userType}
                            className={`w-full btn py-3 mt-4 ${!userType ? 'bg-gray-400 cursor-not-allowed text-gray-800' : 'bg-green-600 hover:bg-green-700 text-white'}`}
                        >
                            Continue
                        </button>
                    </div>
                );
            case 'login':
            case 'signup':
                const isLogin = step === 'login';
                const isAdminPortal = userType === 'Admin'; // Check if admin portal is selected
                return (
                    <div className="w-full max-w-lg mx-auto bg-white p-8 rounded-2xl shadow-2xl border border-blue-200 animate-in fade-in duration-700">
                        <h2 className="text-3xl font-bold text-gray-900 mb-6 text-center">{userType} Portal</h2>
                        {renderMessage()}
                        <div className="flex justify-center mb-6">
                            <button
                                onClick={() => { setStep('login'); clearMessage(); }}
                                className={`px-6 py-2 rounded-l-full font-semibold transition duration-200 ${isLogin ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600 hover:bg-gray-300'} ${isAdminPortal ? 'rounded-r-full' : ''}`}
                            >
                                Sign In
                            </button>
                            {/* Hide Signup button for Admin Portal */}
                            {!isAdminPortal && (
                                <button
                                    onClick={() => { setStep('signup'); clearMessage(); }}
                                    className={`px-6 py-2 rounded-r-full font-semibold transition duration-200 ${!isLogin ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600 hover:bg-gray-300'}`}
                                >
                                    Sign Up
                                </button>
                            )}
                        </div>
                        {isLogin ? renderLoginForm() : !isAdminPortal ? renderSignupForm() : (
                            <div className="text-center p-8 bg-gray-100 rounded-lg text-gray-700 border border-gray-300">
                                <Lock className="w-8 h-8 mx-auto text-red-500 mb-2" />
                                <p className="font-semibold">Administrative accounts cannot be created via this portal.</p>
                                <p className="text-sm mt-1">Please use the default credentials to access the Admin Dashboard.</p>
                            </div>
                        )}
                    </div>
                );
            case 'dashboard':
                return (
                    <div className="w-full max-w-4xl mx-auto p-8 bg-white rounded-2xl shadow-2xl border border-blue-200 animate-in fade-in duration-700">
                        {renderDashboard()}
                    </div>
                );
            default:
                return null;
        }
    };

    return (
        <div className="min-h-screen flex flex-col items-center p-4 bg-blue-50 font-['Poppins'] relative">
            {/* Venture Logo (Bottom Right) - Placeholder for \assets\logos\Code_v.png */}
            <img 
                src="https://placehold.co/200x200/FFFFFF/1E40AF?text=LeafCore%20Labs" 
                alt="Code V Venture Logo" 
                className="absolute bottom-8 right-8 w-16 h-16 rounded-full shadow-lg border-2 border-blue-400 hidden sm:block"
            />
            
            {/* Logo */}
            <div className="mb-8 mt-12">
                <h1 className="text-5xl font-bold text-blue-900 tracking-wider">Pramān</h1>
                <p className="text-gray-600 text-center text-sm">Authenticity, Verified.</p>
            </div>

            {renderContent()}

            {/* Footer */}
            <footer className="mt-12 mb-4 text-center text-gray-500 text-xs">
                Made with ❤️ by LeafCore Labs
            </footer>
        </div>
    );
};

export default App;
