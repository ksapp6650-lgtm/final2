import { useState, useEffect } from 'react';
import { Target, Zap, Award, TrendingUp } from 'lucide-react';
import { supabase } from '../lib/supabase';

export function Dashboard() {
  const [totalPoints, setTotalPoints] = useState(0);
  const [labsCompleted, setLabsCompleted] = useState(0);
  const [currentStreak, setCurrentStreak] = useState(0);
  const [skillLevel, setSkillLevel] = useState('Beginner');

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const { data: progressData, error } = await supabase
        .from('user_progress')
        .select('*')
        .eq('user_id', 'default_user');

      if (error) throw error;

      if (progressData) {
        const points = progressData.reduce((sum, item) => sum + item.points, 0);
        setTotalPoints(points);
        setLabsCompleted(progressData.length);

        if (progressData.length === 0) {
          setSkillLevel('Beginner');
        } else if (progressData.length < 4) {
          setSkillLevel('Beginner');
        } else if (progressData.length < 8) {
          setSkillLevel('Intermediate');
        } else {
          setSkillLevel('Advanced');
        }
      }

      const { data: activityData } = await supabase
        .from('daily_activity')
        .select('activity_date')
        .eq('user_id', 'default_user')
        .order('activity_date', { ascending: false });

      if (activityData && activityData.length > 0) {
        const streak = calculateStreak(activityData.map(a => a.activity_date));
        setCurrentStreak(streak);
      }
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    }
  };

  const calculateStreak = (dates: string[]) => {
    if (dates.length === 0) return 0;

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    const sortedDates = dates
      .map(d => new Date(d))
      .sort((a, b) => b.getTime() - a.getTime());

    const mostRecent = sortedDates[0];
    mostRecent.setHours(0, 0, 0, 0);

    if (mostRecent.getTime() !== today.getTime() && mostRecent.getTime() !== yesterday.getTime()) {
      return 0;
    }

    let streak = 0;
    let currentDate = new Date(today);
    currentDate.setHours(0, 0, 0, 0);

    for (const date of sortedDates) {
      const checkDate = new Date(date);
      checkDate.setHours(0, 0, 0, 0);

      if (checkDate.getTime() === currentDate.getTime()) {
        streak++;
        currentDate.setDate(currentDate.getDate() - 1);
      } else if (checkDate.getTime() < currentDate.getTime()) {
        break;
      }
    }

    return streak;
  };

  const stats = [
    { label: 'Labs Completed', value: labsCompleted.toString(), icon: Target, color: 'bg-blue-500' },
    { label: 'Points Earned', value: totalPoints.toString(), icon: Award, color: 'bg-emerald-500' },
    { label: 'Current Streak', value: `${currentStreak} ${currentStreak === 1 ? 'day' : 'days'}`, icon: Zap, color: 'bg-yellow-500' },
    { label: 'Skill Level', value: skillLevel, icon: TrendingUp, color: 'bg-teal-500' },
  ];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.label}
              className="bg-white rounded-xl shadow-md p-6 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">{stat.label}</p>
                  <p className="text-2xl font-bold mt-1">{stat.value}</p>
                </div>
                <div className={`${stat.color} p-3 rounded-lg`}>
                  <Icon className="h-6 w-6 text-white" />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-gradient-to-r from-emerald-500 to-teal-600 rounded-xl shadow-lg p-8 text-white">
        <h2 className="text-2xl font-bold mb-2">Welcome to CyberSec Academy</h2>
        <p className="text-emerald-50 mb-4">
          Master cybersecurity through hands-on practice with real-world vulnerabilities and tools.
        </p>
        <div className="flex flex-wrap gap-4">
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
            <span className="font-semibold">12 Learning Modules</span>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
            <span className="font-semibold">Interactive Labs</span>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
            <span className="font-semibold">Real-World Tools</span>
          </div>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
            <span className="font-semibold">AI Assistant</span>
          </div>
        </div>
      </div>
    </div>
  );
}
