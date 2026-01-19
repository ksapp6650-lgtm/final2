import { useState, useEffect } from 'react';
import { CheckCircle, Circle, Lock, BookOpen } from 'lucide-react';
import { ModuleContent } from './ModuleContent';
import { supabase } from '../lib/supabase';

interface Module {
  name: string;
  completed: boolean;
  locked: boolean;
  description: string;
  duration: string;
  points: number;
}

interface LearningPathProps {
  onModuleStart?: (moduleName: string, level: string) => void;
}

interface CompletedModules {
  [key: string]: boolean;
}

export function LearningPath({ onModuleStart }: LearningPathProps) {
  const [activeModule, setActiveModule] = useState<{ name: string; level: string } | null>(null);
  const [completedModules, setCompletedModules] = useState<CompletedModules>({});
  const [isLoading, setIsLoading] = useState(true);

  const initialPaths = [
    {
      level: 'Beginner',
      color: 'green',
      modules: [
        {
          name: 'Introduction to Web Security',
          completed: false,
          locked: false,
          description: 'Learn the fundamentals of web security and common attack vectors.',
          duration: '30 mins',
          points: 100,
        },
        {
          name: 'SQL Injection Basics',
          completed: false,
          locked: false,
          description: 'Understand how SQL injection attacks work and how to exploit them.',
          duration: '45 mins',
          points: 150,
        },
        {
          name: 'Cross-Site Scripting (XSS)',
          completed: false,
          locked: false,
          description: 'Learn about reflected, stored, and DOM-based XSS vulnerabilities.',
          duration: '40 mins',
          points: 150,
        },
        {
          name: 'Basic Authentication',
          completed: false,
          locked: false,
          description: 'Explore common authentication vulnerabilities and bypass techniques.',
          duration: '35 mins',
          points: 100,
        },
      ],
    },
    {
      level: 'Intermediate',
      color: 'yellow',
      modules: [
        {
          name: 'Advanced SQL Injection',
          completed: false,
          locked: true,
          description: 'Master blind SQL injection and advanced exploitation techniques.',
          duration: '60 mins',
          points: 200,
        },
        {
          name: 'CSRF Attacks',
          completed: false,
          locked: true,
          description: 'Understand Cross-Site Request Forgery and token validation.',
          duration: '45 mins',
          points: 150,
        },
        {
          name: 'Session Management',
          completed: false,
          locked: true,
          description: 'Learn about session fixation and hijacking attacks.',
          duration: '50 mins',
          points: 175,
        },
        {
          name: 'File Upload Vulnerabilities',
          completed: false,
          locked: true,
          description: 'Exploit unrestricted file upload functionality.',
          duration: '55 mins',
          points: 175,
        },
      ],
    },
    {
      level: 'Advanced',
      color: 'red',
      modules: [
        {
          name: 'XXE Exploitation',
          completed: false,
          locked: true,
          description: 'Master XML External Entity injection attacks.',
          duration: '70 mins',
          points: 250,
        },
        {
          name: 'SSRF Attacks',
          completed: false,
          locked: true,
          description: 'Learn Server-Side Request Forgery exploitation.',
          duration: '65 mins',
          points: 225,
        },
        {
          name: 'Deserialization Attacks',
          completed: false,
          locked: true,
          description: 'Exploit insecure deserialization vulnerabilities.',
          duration: '75 mins',
          points: 250,
        },
        {
          name: 'Advanced Exploit Chains',
          completed: false,
          locked: true,
          description: 'Chain multiple vulnerabilities for maximum impact.',
          duration: '90 mins',
          points: 300,
        },
      ],
    },
  ];

  const colorClasses = {
    green: {
      bg: 'bg-green-100',
      text: 'text-green-800',
      border: 'border-green-200',
      gradient: 'from-green-500 to-green-600',
    },
    yellow: {
      bg: 'bg-yellow-100',
      text: 'text-yellow-800',
      border: 'border-yellow-200',
      gradient: 'from-yellow-500 to-yellow-600',
    },
    red: {
      bg: 'bg-red-100',
      text: 'text-red-800',
      border: 'border-red-200',
      gradient: 'from-red-500 to-red-600',
    },
  };

  useEffect(() => {
    loadCompletedModules();
  }, []);

  useEffect(() => {
    const beginnerModules = initialPaths[0].modules.map(m => m.name);
    const intermediateModules = initialPaths[1].modules.map(m => m.name);

    const allBeginnerCompleted = beginnerModules.every(name => completedModules[name]);
    const allIntermediateCompleted = intermediateModules.every(name => completedModules[name]);

    if (allBeginnerCompleted && allIntermediateCompleted) {
      const certificationPercent = (Object.values(completedModules).filter(Boolean).length / 12) * 100;
      const certElement = document.querySelector('[data-cert-progress]');
      if (certElement) {
        certElement.style.width = `${certificationPercent}%`;
        const textElement = document.querySelector('[data-cert-text]');
        if (textElement) {
          textElement.textContent = `${Math.round(certificationPercent)}% Complete`;
        }
      }
    }
  }, [completedModules]);

  const loadCompletedModules = async () => {
    try {
      const { data, error } = await supabase
        .from('user_progress')
        .select('module_name')
        .eq('user_id', 'default_user');

      if (error) throw error;

      if (data) {
        const completed: CompletedModules = {};
        data.forEach((item) => {
          completed[item.module_name] = true;
        });
        setCompletedModules(completed);
      }
    } catch (error) {
      console.error('Error loading progress:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getUpdatedPaths = () => {
    const beginnerModules = initialPaths[0].modules.map(m => m.name);
    const intermediateModules = initialPaths[1].modules.map(m => m.name);

    const allBeginnerCompleted = beginnerModules.every(name => completedModules[name]);
    const allIntermediateCompleted = intermediateModules.every(name => completedModules[name]);

    return initialPaths.map((path, pathIndex) => ({
      ...path,
      modules: path.modules.map((module, moduleIndex) => {
        let isLocked = module.locked;

        if (pathIndex === 1 && allBeginnerCompleted) {
          isLocked = false;
        }

        if (pathIndex === 2 && allIntermediateCompleted) {
          isLocked = false;
        }

        return {
          ...module,
          completed: completedModules[module.name] || false,
          locked: isLocked,
        };
      }),
    }));
  };

  const handleModuleStart = (moduleName: string, levelName: string) => {
    setActiveModule({ name: moduleName, level: levelName });
    onModuleStart?.(moduleName, levelName);
  };

  const handleModuleComplete = async () => {
    if (activeModule) {
      const module = initialPaths
        .flatMap(p => p.modules)
        .find(m => m.name === activeModule.name);

      if (module) {
        try {
          await supabase
            .from('user_progress')
            .insert({
              user_id: 'default_user',
              module_name: activeModule.name,
              module_level: activeModule.level,
              points: module.points,
            });

          const today = new Date().toISOString().split('T')[0];
          const { data: existingActivity } = await supabase
            .from('daily_activity')
            .select('*')
            .eq('user_id', 'default_user')
            .eq('activity_date', today)
            .maybeSingle();

          if (existingActivity) {
            await supabase
              .from('daily_activity')
              .update({ modules_completed: existingActivity.modules_completed + 1 })
              .eq('id', existingActivity.id);
          } else {
            await supabase
              .from('daily_activity')
              .insert({
                user_id: 'default_user',
                activity_date: today,
                modules_completed: 1,
              });
          }

          setCompletedModules({
            ...completedModules,
            [activeModule.name]: true,
          });
        } catch (error) {
          console.error('Error saving progress:', error);
        }
      }
    }
    setActiveModule(null);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Learning Path</h1>
        <p className="text-gray-600 mt-2">
          Follow a structured path to master cybersecurity concepts
        </p>
      </div>

      <div className="space-y-6">
        {getUpdatedPaths().map((path, pathIndex) => {
          const colors = colorClasses[path.color as keyof typeof colorClasses];
          const completedCount = path.modules.filter(m => m.completed).length;
          const totalCount = path.modules.length;
          const isFullyCompleted = completedCount === totalCount;

          return (
            <div key={pathIndex} className="bg-white rounded-xl shadow-md overflow-hidden">
              <div className={`h-2 bg-gradient-to-r ${colors.gradient}`}></div>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <h2 className="text-2xl font-bold text-gray-900">{path.level} Level</h2>
                    {isFullyCompleted && (
                      <span className="px-3 py-1 bg-emerald-100 text-emerald-700 text-sm font-semibold rounded-full">
                        Completed ✓
                      </span>
                    )}
                  </div>
                  <span className={`px-4 py-2 rounded-full font-semibold ${colors.bg} ${colors.text}`}>
                    {completedCount}/{totalCount} Complete
                  </span>
                </div>

                <div className="space-y-3">
                  {path.modules.map((module, moduleIndex) => (
                    <div
                      key={moduleIndex}
                      className={`p-4 rounded-lg border-2 transition-all cursor-pointer ${
                        module.locked
                          ? 'bg-gray-50 border-gray-200 opacity-60'
                          : module.completed
                          ? `${colors.bg} ${colors.border}`
                          : 'bg-white border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => !module.locked && handleModuleStart(module.name, path.level)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start space-x-3 flex-1">
                          {module.locked ? (
                            <Lock className="h-5 w-5 text-gray-400 mt-1" />
                          ) : module.completed ? (
                            <CheckCircle className={`h-5 w-5 ${colors.text} mt-1`} />
                          ) : (
                            <Circle className="h-5 w-5 text-gray-400 mt-1" />
                          )}
                          <div className="flex-1">
                            <h3 className={`font-semibold ${module.locked ? 'text-gray-500' : 'text-gray-900'}`}>
                              {module.name}
                            </h3>
                            {!module.locked && (
                              <>
                                <p className="text-sm text-gray-600 mt-1">{module.description}</p>
                                <p className="text-xs text-gray-500 mt-2">Duration: {module.duration}</p>
                              </>
                            )}
                          </div>
                        </div>
                        {!module.locked && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleModuleStart(module.name, path.level);
                            }}
                            className={`ml-4 px-4 py-2 rounded-lg font-medium transition-all whitespace-nowrap flex-shrink-0 ${
                              module.completed
                                ? `bg-gradient-to-r ${colors.gradient} text-white hover:shadow-lg`
                                : 'bg-emerald-600 text-white hover:bg-emerald-700'
                            }`}
                          >
                            {module.completed ? 'Review' : 'Start'}
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <div className="flex items-start space-x-3">
          <BookOpen className="h-6 w-6 text-blue-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <h3 className="font-semibold text-blue-900 mb-2">Certification Path</h3>
            <p className="text-blue-800 text-sm mb-4">
              Complete all modules to unlock the CyberSec Academy certification and demonstrate your expertise.
            </p>
            <div className="w-full bg-blue-200 rounded-full h-3">
              <div
                data-cert-progress
                className="bg-gradient-to-r from-blue-500 to-blue-600 h-3 rounded-full transition-all duration-500"
                style={{ width: `${(Object.values(completedModules).filter(Boolean).length / 12) * 100}%` }}
              ></div>
            </div>
            <p data-cert-text className="text-sm text-blue-700 mt-2">{Math.round((Object.values(completedModules).filter(Boolean).length / 12) * 100)}% Complete</p>
          </div>
        </div>
      </div>

      {activeModule && (
        <ModuleContent
          moduleName={activeModule.name}
          level={activeModule.level}
          onClose={() => setActiveModule(null)}
          onComplete={handleModuleComplete}
        />
      )}
    </div>
  );
}
