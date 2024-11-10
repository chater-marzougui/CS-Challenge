import { Alert } from "../components/ui/alert";
import AnalysisResults from "../components/ui/analysis_result";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../components/ui/card";
import { env } from "../config/env";
import { Upload, AlertCircle, Loader2 } from "lucide-react";
import { useState } from "react";

// load env variables
const FileAnalyzer = () => {
  const [_, setFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState<string | null>(null);

  const analyzeFile = async (uploadedFile: any) => {
    setAnalyzing(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", uploadedFile);

      const response = await fetch(`${env.VITE_API_URL}/analyze_ai`, {
        method: "POST",
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
    if (droppedFile && droppedFile.name.endsWith(".exe")) {
      setFile(droppedFile);
      await analyzeFile(droppedFile);
    } else {
      setError("Please upload a valid .exe file");
    }
  };

  const handleFileSelect = async (e: any) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith(".exe")) {
      setFile(selectedFile);
      await analyzeFile(selectedFile);
    } else {
      setError("Please select a valid .exe file");
    }
  };

  return (
    <div
      className="min-h-screen bg-[#181f24]"
      style={{ width: "100%", minWidth: "800px", marginTop: "8rem" }}
    >
      <div
        className="max-w-4xl mx-auto space-y-6"
        style={{ width: "100%", minWidth: "800px" }}
      >
        <Card style={{ width: "100%", minWidth: "800px", minHeight: "400px" }}>
          <CardHeader>
            <CardTitle className="text-4xl font-bold text-[#30c48b]">
              EXE File Analyzer
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              onDrop={handleFileDrop}
              style={{ cursor: "pointer", height: "250px" }}
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
          <Alert
            severity="error"
            title="An error occurred"
            message="There was a problem with your request. Please try again."
            icon={<AlertCircle className="h-4 w-4" />}
            onClose={() => console.log("Alert closed")}
            className="custom-alert-class"
          />
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

        {results && <AnalysisResults results={results} />}
      </div>
    </div>
  );
};

export default FileAnalyzer;
