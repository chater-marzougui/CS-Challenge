import React, { useState, useEffect } from 'react';
import {
    Button,
    Card,
    CardContent,
    CardHeader,
    TextField,
    Typography,
    LinearProgress,
    Alert,
    Box,
    Grid,
    Paper,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    ThemeProvider,
    createTheme,
} from '@mui/material';
import { CheckCircle, Cancel, CloudUpload, QuestionAnswer } from '@mui/icons-material';
import { green, grey } from '@mui/material/colors'; // Added import for colors

// Type for individual URL validation status
interface ValidatedUrl {
    url: string;
    isValid: boolean;
}

// Props for URLValidator component
interface URLValidatorProps {
    url: string;
}

// Define the cyber-themed MUI theme
const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: {
            main: '#00ff00', // Neon Green
        },
        secondary: {
            main: '#ff4081', // Bright Pink for contrast
        },
        success: {
            main: '#00e676', // Light Green
        },
        error: {
            main: '#f44336', // Red
        },
        background: {
            default: '#121212', // Dark background
            paper: '#1d1d1d', // Slightly lighter for paper components
        },
        text: {
            primary: '#00ff00', // Neon Green for primary text
            secondary: '#b0b0b0', // Light Grey for secondary text
        },
    },
    typography: {
        fontFamily: 'Roboto, monospace',
        h4: {
            fontWeight: 700,
            color: '#00ff00',
        },
        h6: {
            fontWeight: 600,
            color: '#00ff00',
        },
        body1: {
            color: '#e0e0e0',
        },
        body2: {
            color: '#b0b0b0',
        },
    },
    components: {
        MuiCardHeader: {
            styleOverrides: {
                root: {
                    backgroundColor: '#1a1a1a',
                },
                title: {
                    color: '#00ff00',
                },
                subheader: {
                    color: '#b0b0b0',
                },
            },
        },
        MuiButton: {
            styleOverrides: {
                root: {
                    textTransform: 'none',
                    borderRadius: '8px',
                    boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                    '&:hover': {
                        boxShadow: '0 0 20px rgba(0, 255, 0, 0.7)',
                    },
                },
                containedPrimary: {
                    backgroundColor: '#00ff00',
                    color: '#000',
                    '&:hover': {
                        backgroundColor: '#00e600',
                    },
                },
                containedSecondary: {
                    backgroundColor: '#ff4081',
                    color: '#000',
                    '&:hover': {
                        backgroundColor: '#e040fb',
                    },
                },
            },
        },
        MuiLinearProgress: {
            styleOverrides: {
                root: {
                    height: '8px',
                    borderRadius: '4px',
                },
                bar: {
                    borderRadius: '4px',
                    backgroundColor: '#00ff00',
                },
            },
        },
    },
});

// Utility function to validate URLs
const isValidUrl = (url: string): boolean => {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
};

// URL validation component
const URLValidator: React.FC<URLValidatorProps> = ({ url }) => {
    const isValid = isValidUrl(url.trim());
    return (
        <Box display="flex" alignItems="center" gap={1}>
            {isValid ? (
                <CheckCircle style={{ color: green[500] }} />
            ) : (
                <Cancel style={{ color: grey[500] }} />
            )}
            <Typography variant="body2" color={isValid ? 'success.main' : 'error.main'}>
                {isValid ? 'Valid URL' : 'Invalid URL'}
            </Typography>
        </Box>
    );
};

// Main RAG interface component
const RAGInterface: React.FC = () => {
    const [urls, setUrls] = useState<string>('');
    const [validatedUrls, setValidatedUrls] = useState<ValidatedUrl[]>([]);
    const [question, setQuestion] = useState<string>('');
    const [answer, setAnswer] = useState<string>('');
    const [sources, setSources] = useState<string[]>([]);
    const [isParsing, setIsParsing] = useState<boolean>(false);
    const [isAnswering, setIsAnswering] = useState<boolean>(false);
    const [error, setError] = useState<string>('');
    const [success, setSuccess] = useState<string>('');
    const [parseProgress, setParseProgress] = useState<number>(0);
    const [isDatabaseReady, setIsDatabaseReady] = useState<boolean>(false);

    // Update URL validation status whenever `urls` changes
    useEffect(() => {
        const urlList: string[] = urls.split('\n').filter((url) => url.trim());
        setValidatedUrls(
            urlList.map((url) => ({
                url: url.trim(),
                isValid: isValidUrl(url.trim()),
            }))
        );
    }, [urls]);

    // Handle URL parsing
    const handleParse = async (): Promise<void> => {
        const validUrls: string[] = validatedUrls.filter((u) => u.isValid).map((u) => u.url);

        if (validUrls.length === 0) {
            setError('Please provide at least one valid URL.');
            return;
        }

        setIsParsing(true);
        setError('');
        setSuccess('');
        setParseProgress(0);
        setIsDatabaseReady(false);

        try {
            const progressInterval = setInterval(() => {
                setParseProgress((prev) => Math.min(prev + 10, 90));
            }, 500);

            // Replace with your actual API URL for parsing
            const parseApiUrl = 'http://localhost:8000/parse';

            // Make an API call to parse URLs
            const parseResponse = await fetch(parseApiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ urls: validUrls }),
            });

            clearInterval(progressInterval);
            setParseProgress(100);

            if (parseResponse.ok) {
                const parseData = await parseResponse.json();
                console.log('Parsing API response:', parseData);

                setSuccess('URLs parsed and knowledge base initialized successfully.');
                setIsDatabaseReady(true);
            } else {
                const errorData = await parseResponse.json();
                setError(errorData.detail || 'Failed to parse URLs.');
            }
        } catch (err) {
            console.error(err);
            setError('An error occurred while parsing URLs.');
        } finally {
            setIsParsing(false);
        }
    };

    // Handle answer retrieval
    const handleGetAnswer = async (): Promise<void> => {
        if (!question.trim()) {
            setError('Please enter a question.');
            return;
        }

        setIsAnswering(true);
        setError('');
        setSuccess('');
        setAnswer('');
        setSources([]);

        try {
            // Replace with your actual API URL for answer retrieval
            const answerApiUrl = 'http://localhost:8000/answer';

            // Make an API call to get an answer
            const answerResponse = await fetch(answerApiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ question: question }),
            });

            if (answerResponse.ok) {
                const answerData = await answerResponse.json();
                console.log('Answer API response:', answerData);

                setAnswer(answerData.answer || "Sorry, I don't have an answer to that.");
                setSources(answerData.source_documents || []);
                setSuccess('Answer retrieved successfully.');
            } else {
                const errorData = await answerResponse.json();
                setError(errorData.detail || 'Failed to get an answer.');
            }
        } catch (err) {
            console.error(err);
            setError('An error occurred while retrieving the answer.');
        } finally {
            setIsAnswering(false);
        }
    };

    const validUrlCount: number = validatedUrls.filter((u) => u.isValid).length;
    const totalUrlCount: number = validatedUrls.length;

    return (
        <ThemeProvider theme={theme}>
            <Box minHeight="100vh" bgcolor="background.default" paddingY={4}>
                <Grid container spacing={4} justifyContent="center">
                    <Grid item xs={11} md={8}>
                        {/* Header Section */}
                        <Paper
                            elevation={3}
                            sx={{
                                padding: 3,
                                marginBottom: 4,
                                background: 'linear-gradient(135deg, #00ff00 0%, #007700 100%)',
                                borderRadius: '12px',
                                boxShadow: '0 0 20px rgba(0, 255, 0, 0.5)',
                            }}
                        >
                            <Typography variant="h4" gutterBottom>
                                Zephyr-7B RAG System
                            </Typography>
                            <Typography variant="subtitle1" color="textSecondary">
                                Parse your knowledge base URLs and ask questions to retrieve insightful answers.
                            </Typography>
                        </Paper>

                        {/* Input Section */}
                        <Card
                            variant="outlined"
                            sx={{
                                marginBottom: 4,
                                backgroundColor: '#1d1d1d',
                                border: '1px solid #00ff00',
                                borderRadius: '12px',
                                boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                            }}
                        >
                            <CardHeader
                                title="Knowledge Base Setup"
                                subheader="Enter the URLs for your knowledge base"
                            />
                            <CardContent>
                                <TextField
                                    multiline
                                    rows={6}
                                    fullWidth
                                    placeholder="https://example.com\nhttps://another-example.com"
                                    value={urls}
                                    onChange={(e) => setUrls(e.target.value)}
                                    variant="outlined"
                                    margin="normal"
                                    label="Enter URLs"
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: '#00ff00',
                                            },
                                            '&:hover fieldset': {
                                                borderColor: '#00e600',
                                            },
                                            '&.Mui-focused fieldset': {
                                                borderColor: '#00ff00',
                                            },
                                        },
                                        '& .MuiInputLabel-root': {
                                            color: '#00ff00',
                                        },
                                        '& .MuiInputLabel-root.Mui-focused': {
                                            color: '#00ff00',
                                        },
                                    }}
                                />
                                <Typography variant="body2" color="textSecondary" gutterBottom>
                                    {totalUrlCount} URLs entered, {validUrlCount} are valid
                                </Typography>
                                <List dense>
                                    {validatedUrls.map((item, index) => (
                                        <ListItem key={index}>
                                            <ListItemIcon>
                                                {item.isValid ? (
                                                    <CheckCircle style={{ color: green[500] }} />
                                                ) : (
                                                    <Cancel style={{ color: grey[500] }} />
                                                )}
                                            </ListItemIcon>
                                            <ListItemText
                                                primary={item.url}
                                                primaryTypographyProps={{
                                                    style: { wordBreak: 'break-all', color: '#e0e0e0' },
                                                }}
                                            />
                                        </ListItem>
                                    ))}
                                </List>
                                <Box display="flex" alignItems="center" gap={2} marginTop={2}>
                                    <Button
                                        variant="contained"
                                        color="primary"
                                        startIcon={<CloudUpload />}
                                        onClick={handleParse}
                                        disabled={isParsing || validUrlCount === 0}
                                    >
                                        {isParsing ? 'Parsing...' : 'Parse URLs'}
                                    </Button>
                                    {isParsing && (
                                        <Box width="100%">
                                            <LinearProgress variant="determinate" value={parseProgress} />
                                        </Box>
                                    )}
                                </Box>
                                {error && (
                                    <Alert
                                        severity="error"
                                        sx={{
                                            marginTop: 2,
                                            backgroundColor: '#333',
                                            color: '#ff4d4d',
                                            border: '1px solid #ff4d4d',
                                        }}
                                    >
                                        {error}
                                    </Alert>
                                )}
                                {success && (
                                    <Alert
                                        severity="success"
                                        sx={{
                                            marginTop: 2,
                                            backgroundColor: '#333',
                                            color: '#00ff00',
                                            border: '1px solid #00ff00',
                                        }}
                                    >
                                        {success}
                                    </Alert>
                                )}
                            </CardContent>
                        </Card>

                        {/* Question Section */}
                        <Card
                            variant="outlined"
                            sx={{
                                marginBottom: 4,
                                backgroundColor: '#1d1d1d',
                                border: '1px solid #00ff00',
                                borderRadius: '12px',
                                boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                            }}
                        >
                            <CardHeader
                                title="Ask a Question"
                                subheader={
                                    isDatabaseReady
                                        ? "Your knowledge base is ready. You can ask questions now."
                                        : "Parse URLs first to initialize the knowledge base."
                                }
                            />
                            <CardContent>
                                <TextField
                                    fullWidth
                                    placeholder="Enter your question..."
                                    value={question}
                                    onChange={(e) => setQuestion(e.target.value)}
                                    variant="outlined"
                                    margin="normal"
                                    label="Your Question"
                                    disabled={!isDatabaseReady}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: '#00ff00',
                                            },
                                            '&:hover fieldset': {
                                                borderColor: '#00e600',
                                            },
                                            '&.Mui-focused fieldset': {
                                                borderColor: '#00ff00',
                                            },
                                        },
                                        '& .MuiInputLabel-root': {
                                            color: '#00ff00',
                                        },
                                        '& .MuiInputLabel-root.Mui-focused': {
                                            color: '#00ff00',
                                        },
                                    }}
                                />
                                <Box display="flex" alignItems="center" gap={2} marginTop={2}>
                                    <Button
                                        variant="contained"
                                        color="secondary"
                                        startIcon={<QuestionAnswer />}
                                        onClick={handleGetAnswer}
                                        disabled={isAnswering || !isDatabaseReady || !question.trim()}
                                    >
                                        {isAnswering ? 'Thinking...' : 'Get Answer'}
                                    </Button>
                                    {isAnswering && (
                                        <LinearProgress
                                            sx={{ flexGrow: 1, height: '8px', borderRadius: '4px' }}
                                        />
                                    )}
                                </Box>
                                {error && (
                                    <Alert
                                        severity="error"
                                        sx={{
                                            marginTop: 2,
                                            backgroundColor: '#333',
                                            color: '#ff4d4d',
                                            border: '1px solid #ff4d4d',
                                        }}
                                    >
                                        {error}
                                    </Alert>
                                )}
                                {success && (
                                    <Alert
                                        severity="success"
                                        sx={{
                                            marginTop: 2,
                                            backgroundColor: '#333',
                                            color: '#00ff00',
                                            border: '1px solid #00ff00',
                                        }}
                                    >
                                        {success}
                                    </Alert>
                                )}
                                {answer && (
                                    <Card
                                        variant="outlined"
                                        sx={{
                                            marginTop: 4,
                                            backgroundColor: '#1a1a1a',
                                            border: '1px solid #00ff00',
                                            borderRadius: '12px',
                                            boxShadow: '0 0 10px rgba(0, 255, 0, 0.5)',
                                        }}
                                    >
                                        <CardHeader title="Answer" />
                                        <CardContent>
                                            <Typography variant="body1" gutterBottom>
                                                {answer}
                                            </Typography>
                                        </CardContent>
                                    </Card>
                                )}
                            </CardContent>
                        </Card>
                    </Grid>
                </Grid>
            </Box>
        </ThemeProvider>
    );
}

export default RAGInterface;
