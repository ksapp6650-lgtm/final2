import { useState, useEffect } from 'react';
import { Trophy, Target, Zap, Award, Calendar, TrendingUp } from 'lucide-react';
import { supabase } from '../lib/supabase';

export function Progress() {
  const [totalPoints, setTotalPoints] = useState(0);
  const [labsCompleted, setLabsCompleted] = useState(0);
  const [currentStreak, setCurrentStreak] = useState(0);
  const [beginnerProgress, setBeginnerProgress] = useState(0);
  const [intermediateProgress, setIntermediateProgress] = useState(0);
  const [advancedProgress, setAdvancedProgress] = useState(0);
  const [recentActivity, setRecentActivity] = useState<Array<{ type: string; name: string; date: string; points: number }>>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadProgressData();
  }, []);

  const loadProgressData = async () => {
    try {
      const { data: progressData, error } = await supabase
        .from('user_progress')
        .select('*')
        .eq('user_id', 'default_user')
        .order('completed_at', { ascending: false });

      if (error) throw error;

      if (progressData) {
        const points = progressData.reduce((sum, item) => sum + item.points, 0);
        setTotalPoints(points);
        setLabsCompleted(progressData.length);

        const beginnerCount = progressData.filter(p => p.module_level === 'Beginner').length;
        const intermediateCount = progressData.filter(p => p.module_level === 'Intermediate').length;
        const advancedCount = progressData.filter(p => p.module_level === 'Advanced').length;

        setBeginnerProgress((beginnerCount / 4) * 100);
        setIntermediateProgress((intermediateCount / 4) * 100);
        setAdvancedProgress((advancedCount / 4) * 100);

        const recentActivities = progressData.slice(0, 5).map(item => ({
          type: 'module',
          name: item.module_name,
          date: formatDate(item.completed_at),
          points: item.points,
        }));
        setRecentActivity(recentActivities);
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
      console.error('Error loading progress:', error);
    } finally {
      setIsLoading(false);
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

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    date.setHours(0, 0, 0, 0);
    today.setHours(0, 0, 0, 0);
    yesterday.setHours(0, 0, 0, 0);

    if (date.getTime() === today.getTime()) return 'Today';
    if (date.getTime() === yesterday.getTime()) return 'Yesterday';

    const diffDays = Math.floor((today.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    if (diffDays < 7) return `${diffDays} days ago`;

    return date.toLocaleDateString();
  };

  const achievements = [
    {
      name: 'First Steps',
      description: 'Complete your first module',
      icon: Target,
      earned: labsCompleted >= 1,
      points: 50,
    },
    {
      name: 'Beginner Master',
      description: 'Complete all Beginner modules',
      icon: Award,
      earned: beginnerProgress === 100,
      points: 100,
    },
    {
      name: 'Intermediate Expert',
      description: 'Complete all Intermediate modules',
      icon: Award,
      earned: intermediateProgress === 100,
      points: 150,
    },
    {
      name: 'Dedicated Learner',
      description: 'Maintain a 3-day streak',
      icon: Zap,
      earned: currentStreak >= 3,
      points: 75,
    },
    {
      name: 'Week Warrior',
      description: 'Practice for 7 consecutive days',
      icon: Calendar,
      earned: currentStreak >= 7,
      points: 150,
    },
    {
      name: 'Advanced Hacker',
      description: 'Complete all Advanced modules',
      icon: Trophy,
      earned: advancedProgress === 100,
      points: 250,
    },
  ];

  const stats = [
    { label: 'Total Points', value: totalPoints.toString(), icon: Trophy, color: 'text-yellow-600 bg-yellow-100' },
    { label: 'Labs Completed', value: `${labsCompleted}/12`, icon: Target, color: 'text-blue-600 bg-blue-100' },
    { label: 'Current Streak', value: `${currentStreak} ${currentStreak === 1 ? 'day' : 'days'}`, icon: Zap, color: 'text-orange-600 bg-orange-100' },
  ];

  const nextGoalLabs = labsCompleted < 5 ? 5 : labsCompleted < 8 ? 8 : 12;
  const labsRemaining = Math.max(0, nextGoalLabs - labsCompleted);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-emerald-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading your progress...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Your Progress</h1>
        <p className="text-gray-600 mt-2">Track your learning journey and achievements</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {stats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="bg-white rounded-xl shadow-md p-6">
              <div className="flex items-center justify-between mb-2">
                <div className={`p-3 rounded-lg ${stat.color}`}>
                  <Icon className="h-6 w-6" />
                </div>
              </div>
              <p className="text-gray-600 text-sm">{stat.label}</p>
              <p className="text-2xl font-bold text-gray-900 mt-1">{stat.value}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white rounded-xl shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Learning Progress</h2>

          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">Beginner Level</span>
                <span className="text-sm font-semibold text-emerald-600">{Math.round(beginnerProgress)}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-3">
                <div className="bg-gradient-to-r from-green-500 to-green-600 h-3 rounded-full transition-all duration-500" style={{ width: `${beginnerProgress}%` }}></div>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">Intermediate Level</span>
                <span className="text-sm font-semibold text-yellow-600">{Math.round(intermediateProgress)}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-3">
                <div className="bg-gradient-to-r from-yellow-500 to-yellow-600 h-3 rounded-full transition-all duration-500" style={{ width: `${intermediateProgress}%` }}></div>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">Advanced Level</span>
                <span className="text-sm font-semibold text-red-600">{Math.round(advancedProgress)}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-3">
                <div className="bg-gradient-to-r from-red-500 to-red-600 h-3 rounded-full transition-all duration-500" style={{ width: `${advancedProgress}%` }}></div>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-6 border-t border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
            {recentActivity.length > 0 ? (
              <div className="space-y-3">
                {recentActivity.map((activity, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-medium text-gray-900">{activity.name}</p>
                      <p className="text-sm text-gray-600">{activity.date}</p>
                    </div>
                    <span className="px-3 py-1 bg-emerald-100 text-emerald-700 rounded-full text-sm font-semibold">
                      +{activity.points} pts
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 bg-gray-50 rounded-lg">
                <p className="text-gray-600">No activity yet. Start completing modules to see your progress here.</p>
              </div>
            )}
          </div>
        </div>

        <div className="bg-white rounded-xl shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Achievements</h2>
          <div className="space-y-3">
            {achievements.map((achievement, index) => {
              const Icon = achievement.icon;
              return (
                <div
                  key={index}
                  className={`p-4 rounded-lg border-2 transition-all ${
                    achievement.earned
                      ? 'bg-emerald-50 border-emerald-200'
                      : 'bg-gray-50 border-gray-200 opacity-60'
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    <div
                      className={`p-2 rounded-lg ${
                        achievement.earned ? 'bg-emerald-500' : 'bg-gray-400'
                      }`}
                    >
                      <Icon className="h-5 w-5 text-white" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900 text-sm">{achievement.name}</h3>
                      <p className="text-xs text-gray-600 mt-1">{achievement.description}</p>
                      <p className="text-xs text-gray-500 mt-1">{achievement.points} points</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {labsCompleted > 0 && labsRemaining > 0 && (
        <div className="bg-gradient-to-r from-emerald-500 to-teal-600 rounded-xl shadow-lg p-8 text-white">
          <h2 className="text-2xl font-bold mb-2">Keep Going!</h2>
          <p className="text-emerald-50 mb-4">
            You're making great progress! Complete more modules to unlock achievements.
          </p>
          <div className="flex items-center space-x-4">
            <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
              <span className="font-semibold">Next Goal: Complete {nextGoalLabs} modules</span>
            </div>
            <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2">
              <span className="font-semibold">{labsRemaining} more to go!</span>
            </div>
          </div>
        </div>
      )}

      {labsCompleted === 0 && (
        <div className="bg-gradient-to-r from-blue-500 to-blue-600 rounded-xl shadow-lg p-8 text-white">
          <h2 className="text-2xl font-bold mb-2">Ready to Start?</h2>
          <p className="text-blue-50 mb-4">
            Begin your cybersecurity journey by completing your first module in the Learning Path section.
          </p>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2 inline-block">
            <span className="font-semibold">Start with Beginner modules</span>
          </div>
        </div>
      )}

      {labsCompleted === 12 && (
        <div className="bg-gradient-to-r from-yellow-500 to-orange-500 rounded-xl shadow-lg p-8 text-white">
          <h2 className="text-2xl font-bold mb-2">Congratulations!</h2>
          <p className="text-yellow-50 mb-4">
            You've completed all modules! You're now a certified CyberSec Academy expert.
          </p>
          <div className="bg-white/20 backdrop-blur-sm rounded-lg px-4 py-2 inline-block">
            <span className="font-semibold">Total Points: {totalPoints}</span>
          </div>
        </div>
      )}
    </div>
  );
}
