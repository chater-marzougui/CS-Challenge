import { useState } from 'react';
import { Box, CssBaseline, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Typography, Toolbar } from '@mui/material';
import HomeIcon from '@mui/icons-material/Home';
import InfoIcon from '@mui/icons-material/Info';
import SettingsIcon from '@mui/icons-material/Settings';
import reactLogo from './assets/react.svg';
import ThreatPostList from './pages/blacklist';
import Rag from './pages/rag';
import FileAnalyzer from './pages/filaAnalyser';
import './App.css';

// Define the width of the drawer
const drawerWidth = 240;

function App() {
  const [page, setPage] = useState('Home');

  // Function to render content based on the selected page
  const renderContent = () => {
    switch (page) {
      case 'Dashboard':
        return <Typography variant="h4">DashBoard</Typography>;
      case 'Black List':
        return <ThreatPostList /> // <ThreatPostList />;
      case 'File analyzer': 
        return <FileAnalyzer />;
      case 'rag': 
        return <Rag />;
      default:
        return <Typography variant="h4">Welcome</Typography>;
    }
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />
      {/* AppBar for the top toolbar
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <Typography variant="h6" noWrap component="div">
            My App
          </Typography>
        </Toolbar>
      </AppBar> */}
      
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' },
        }}
      >
        <Toolbar style={{marginTop: "80px"}}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%' }}>
            <img src={reactLogo} alt="Logo" style={{ width: 140, height: 140 }} />
          </Box>
        </Toolbar>
        <List>
          {['Dashboard', 'Black List', 'File analyzer','rag'].map((text, index) => (
            <ListItemButton key={text} onClick={() => setPage(text)}>
              <ListItemIcon>
                {index === 0 ? <HomeIcon /> : index === 1 ? <InfoIcon /> : <SettingsIcon />}
              </ListItemIcon>
              <ListItemText primary={text} />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, p: 3, mt: 8, width: "100%" }}>
        <Toolbar />
        {renderContent()}
      </Box>
    </Box>
  );
}

export default App;
