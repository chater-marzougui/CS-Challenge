import React, { createContext, useContext, useState } from "react";

// Define types for node data and context
interface NodeData {
  id: string;
  name: string;
  type: string;
  status: string;
  rlAgentData: {
    activityLevel: number;
    lastAction: string;
  };
}

interface DrawerContextType {
  isOpen: boolean;
  selectedNode: NodeData | null;
  openDrawer: (node: NodeData) => void;
  closeDrawer: () => void;
}

// Initialize the context
const DrawerContext = createContext<DrawerContextType | undefined>(undefined);

// Provide the context to the components
export const DrawerProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);

  const openDrawer = (node: NodeData) => {
    setSelectedNode(node);
    setIsOpen(true);
  };

  const closeDrawer = () => {
    setIsOpen(false);
    setSelectedNode(null);
  };

  return (
    <DrawerContext.Provider value={{ isOpen, selectedNode, openDrawer, closeDrawer }}>
      {children}
    </DrawerContext.Provider>
  );
};

// Custom hook to use the Drawer context
export const useDrawerContext = () => {
  const context = useContext(DrawerContext);
  if (!context) {
    throw new Error("useDrawerContext must be used within a DrawerProvider");
  }
  return context;
};
