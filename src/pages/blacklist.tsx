import React, { useState, useEffect } from 'react';
import useBlacklist from '../hooks/useBlacklist';
import { AppBar, Toolbar, Typography } from '@mui/material';
import { Shield, User, AlertTriangle, Ban, CheckCircle } from 'lucide-react';
import { Card, CardContent } from '@mui/material';
import { Alert, AlertDescription } from '../components/ui/alert';

const mockPosts: Post[] = [
    {
      id: '1',
      name: 'Post 1',
      text: 'This is a threat post with level 2 threat.',
      threatLevel: 2,
      creatorId: 'user1'
    },
    {
      id: '2',
      name: 'Post 2',
      text: 'This is a threat post with level 4 threat.',
      threatLevel: 4,
      creatorId: 'user2'
    },
    {
      id: '3',
      name: 'Post 3',
      text: 'This is a threat post with level 1 threat.',
      threatLevel: 1,
      creatorId: 'user3'
    },
    {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat., This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.,This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      },
      {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      },
      {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      },
      {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      },
      {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      },
      {
        id: '1',
        name: 'Post 1',
        text: 'This is a threat post with level 2 threat.',
        threatLevel: 2,
        creatorId: 'user1'
      },
      {
        id: '2',
        name: 'Post 2',
        text: 'This is a threat post with level 4 threat.',
        threatLevel: 4,
        creatorId: 'user2'
      },
      {
        id: '3',
        name: 'Post 3',
        text: 'This is a threat post with level 1 threat.',
        threatLevel: 1,
        creatorId: 'user3'
      }
  ];

interface Post {
  id: string;
  name: string;
  text: string;
  threatLevel: 1 | 2 | 3 | 4;
  creatorId: string;
}

const ThreatPostList: React.FC = () => {
  const [posts, setPosts] = useState<Post[]>([]);
  const { blacklist, addToBlacklist, removeFromBlacklist } = useBlacklist();

  useEffect(() => {
    // Fetch posts from the server
    fetchPosts();
  }, []);

  const fetchPosts = async () => {
    try {
    //   const response = await fetch('/api/posts');
    //   const data = await response.json();
      setPosts(mockPosts);
    } catch (error) {
      console.error('Error fetching posts:', error);
    }
  };

  const handleAddToBlacklist = (creatorId: string) => {
    addToBlacklist(creatorId);
  };

  const handleRemoveFromBlacklist = (creatorId: string) => {
    removeFromBlacklist(creatorId);
  };

  const getThreatLevelInfo = (level: 1 | 2 | 3 | 4) => {
    const levels = {
      1: {
        label: 'Low',
        color: 'text-green-500',
        bgColor: 'bg-green-50',
        borderColor: 'border-green-200',
        icon: CheckCircle
      },
      2: {
        label: 'Moderate',
        color: 'text-yellow-500',
        bgColor: 'bg-yellow-50',
        borderColor: 'border-yellow-200',
        icon: Shield
      },
      3: {
        label: 'High',
        color: 'text-orange-500',
        bgColor: 'bg-orange-50',
        borderColor: 'border-orange-200',
        icon: AlertTriangle
      },
      4: {
        label: 'Critical',
        color: 'text-red-500',
        bgColor: 'bg-red-50',
        borderColor: 'border-red-200',
        icon: Ban
      }
    };
    return levels[level] || levels[1];
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
                <Toolbar>
                <Typography variant="h6" noWrap component="div" style={{ color:"white", width: "100%", textAlign: "center" }}>
                        Threat Posts
                </Typography>
                </Toolbar>
            </AppBar>
            <p className="mt-1 text-sm text-gray-500">
              Monitoring and managing potential security threats
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <Alert className="bg-gray-50 border-gray-200">
              <AlertDescription>
                <span className="font-medium">{posts.filter(p => blacklist.includes(p.creatorId)).length}</span> posts blacklisted
              </AlertDescription>
            </Alert>
          </div>
        </div>

        <div className="grid gap-6">
          {posts.filter((post) => blacklist.includes(post.creatorId)).map((post) => {
            const threatInfo = getThreatLevelInfo(post.threatLevel);
            const ThreatIcon = threatInfo.icon;

            return (
              <Card 
                key={post.id}
                style={{ width: '100%', minHeight: '240px' }}
                className={`transition-all duration-200 hover:shadow-lg ${threatInfo.borderColor} border-l-4`}
              >
                <CardContent className="p-6">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-4">
                      <div className={`p-2 rounded-full ${threatInfo.bgColor}`}>
                        <User className={`h-6 w-6 ${threatInfo.color}`} />
                      </div>
                      <div>
                        <h3 className="font-semibold text-gray-900">{post.name}</h3>
                        <div className="mt-1 flex items-center space-x-2">
                          <ThreatIcon className={`h-4 w-4 ${threatInfo.color}`} />
                          <span className={`text-sm font-medium ${threatInfo.color}`}>
                            {threatInfo.label} Threat Level
                          </span>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={() => handleRemoveFromBlacklist(post.creatorId)}
                      className={`inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium
                        ${threatInfo.bgColor} ${threatInfo.color}
                        hover:bg-gray-100 transition-colors duration-200`}
                    >
                      <Ban className="h-4 w-4 mr-1.5" />
                      Remove from Blacklist
                    </button>
                  </div>

                  <div className={`mt-4 p-4 rounded-lg ${threatInfo.bgColor}`}>
                    <p className="text-gray-700 text-xl">{post.text}</p>
                  </div>

                  <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
                    <div className="flex items-center space-x-4">
                      <span>ID: {post.creatorId.length > 8 ? post.creatorId.slice(0, 8) : post.creatorId}</span>
                    
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ThreatPostList;


