import { useState } from 'react';
import { Upload, AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Alert, AlertDescription } from '../components/ui/alert';
import { env } from '../config/env';
// load env variables
const FileAnalyzer = () => {
  const [_ , setFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState<string | null>(null);

  const analyzeFile = async (uploadedFile: any) => {
    setAnalyzing(true);
    setError(null);
    
    try {
      const formData = new FormData();
      formData.append('file', uploadedFile);

      const response = await fetch(`${env.VITE_API_URL}/analyze`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`);
      }

      const data = await response.json();
      setResults(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFileDrop = async (e: any) => {
    e.preventDefault();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.endsWith('.exe')) {
      setFile(droppedFile);
      await analyzeFile(droppedFile);
    } else {
      setError('Please upload a valid .exe file');
    }
  };

  const handleFileSelect = async (e: any) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith('.exe')) {
      setFile(selectedFile);
      await analyzeFile(selectedFile);
    } else {
      setError('Please select a valid .exe file');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-8" style={{width: "100%", minWidth: "800px" }}>
      <div className="max-w-4xl mx-auto space-y-6" style={{width: "100%", minWidth: "800px" }}>
        <Card style={{width: "100%", minWidth: "800px", minHeight: "400px" }}>
          <CardHeader>
            <CardTitle className="text-4xl font-bold">EXE File Analyzer</CardTitle>
          </CardHeader>
          <CardContent>
            <div
              onDrop={handleFileDrop}
              style={{ cursor: 'pointer', height: '250px' }}
              onDragOver={(e) => e.preventDefault()}
              className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors"
            >
              <input
                type="file"
                accept=".exe"
                onChange={handleFileSelect}
                className="hidden"
                id="file-upload"
              />
              <label
                htmlFor="file-upload"
                className="cursor-pointer flex flex-col items-center"
              >
                <Upload className="h-12 w-12 text-gray-400 mb-4" />
                <span className="text-gray-600 text-3xl">
                  Drag and drop an .exe file here, or click to select
                </span>
                <span className="text-sm text-gray-500 text-2xl mt-2">
                  Only .exe files are supported
                </span>
              </label>
            </div>
          </CardContent>
        </Card>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {analyzing && (
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <Loader2 className="h-6 w-6 animate-spin text-blue-500" />
                <span>Analyzing file...</span>
              </div>
            </CardContent>
          </Card>
        )}

        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <CheckCircle className="h-6 w-6 text-green-500" />
                <span>Analysis Results</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(results).map(([key, value]) => (
                  <div key={key} className="border-b pb-4">
                    <h3 className="font-medium text-gray-700 mb-2">
                      {key.replace(/_/g, ' ').toUpperCase()}
                    </h3>
                    <pre className="bg-gray-50 p-4 rounded-lg overflow-x-auto">
                      {typeof value === 'object' 
                        ? JSON.stringify(value, null, 2)
                        : value!.toString()}
                    </pre>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default FileAnalyzer;